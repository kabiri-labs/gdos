"""Base types shared by every resilience check.

A *check* probes a single GraphQL DoS vector with one bounded request and
classifies the endpoint's behaviour. A check may send a trivial control query
to confirm an ambiguous result, and one check falls back to a second payload
shape when the first cannot settle the question; neither is an escalation.
Checks are read-only with respect to the target: they never loop, never raise
the magnitude of a payload, and always honour the client timeout.

Classification is deliberately conservative in both directions. A verdict of
``PROTECTED`` requires evidence that the payload was refused; a verdict of
``VULNERABLE`` requires evidence that it was *executed*. Everything a probe
cannot attribute to the target's own behaviour — an authentication wall, a
rate limiter, an endpoint that went away — is reported as ``INCONCLUSIVE``
rather than being folded into either of the two conclusive verdicts.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdos.client import GraphQLClient, GraphQLResponse


class Verdict(enum.Enum):
    """Outcome of a single check."""

    PROTECTED = "PROTECTED"
    """The server enforced a limit / rejected the abusive payload."""
    VULNERABLE = "VULNERABLE"
    """The server processed the abusive payload (or showed resource impact)."""
    INCONCLUSIVE = "INCONCLUSIVE"
    """Could not determine — e.g. auth required, throttled, endpoint unhealthy."""
    ERROR = "ERROR"
    """The probe itself failed (network error, unreachable endpoint)."""


class Severity(enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Rejection(enum.Enum):
    """Why the server refused a probe, when it refused one.

    Distinguishing these is the difference between "this endpoint is hardened"
    and "this endpoint never even looked at the payload". Only ``LIMIT`` and
    ``SIZE`` are evidence of a DoS control.
    """

    NONE = "none"
    """Not a rejection."""
    LIMIT = "limit"
    """A depth/complexity/alias/batch limit was enforced."""
    SIZE = "size"
    """The request was refused for its raw size (413/414/431)."""
    AUTH = "auth"
    """Authentication or authorization refusal — says nothing about DoS controls."""
    RATE = "rate"
    """Throttled. Protective, but it may also be the scan throttling itself."""
    VALIDATION = "validation"
    """Refused during validation with no limit-specific message."""


@dataclass
class CheckResult:
    name: str
    vector: str
    verdict: Verdict
    severity: Severity
    summary: str
    remediation: str
    elapsed: float = 0.0
    baseline_elapsed: float = 0.0
    evidence: dict[str, object] = field(default_factory=dict)
    abort_scan: bool = False
    """Set when the endpoint is no longer in a state where further probing
    would produce trustworthy verdicts (or would be responsible)."""


def _phrases(*terms: str) -> re.Pattern[str]:
    """Compile an alternation anchored at a word boundary.

    No trailing boundary, so a term acts as a prefix: ``complex`` matches
    "complexity" and ``throttl`` matches "throttled", while the leading
    boundary keeps ``cost`` out of "Pentecost" and ``limit`` out of "delimiter".
    """
    return re.compile(r"\b(?:%s)" % "|".join(terms), re.IGNORECASE)


_AUTH_PHRASES = _phrases(
    "unauthenticated", "unauthorized", "unauthorised", "not authenticated",
    "authentication", "authorization required", "forbidden", "access denied",
    "permission denied", "insufficient permission", "not permitted",
    "must be logged in", "login required", "invalid token", "expired token",
    "invalid api key", "missing api key", "missing credentials",
    # Spaced forms. "unauthorized" does not match "not authorized", and a
    # message that falls through to VALIDATION is read as a refusal by a DoS
    # control — which is exactly the false-clean auth result to avoid.
    "not authorized", "not authorised", "no permission",
    # Narrower than the bare "not allowed" in _LIMIT_PHRASES on purpose, so
    # "batching is not allowed" still reads as a limit rather than an auth wall.
    "not allowed to access",
)

_RATE_PHRASES = _phrases(
    "rate limit", "rate-limit", "ratelimit", "too many requests",
    "throttl", "quota exceeded", "quota exhausted", "slow down",
)

_SIZE_PHRASES = _phrases(
    "payload too large", "entity too large", "request too large",
    "body too large", "content too large", "uri too long", "header too large",
)

# Phrases that genuinely indicate a DoS control refused the document. Kept
# narrow on purpose: a term here that also occurs in ordinary schema or data
# vocabulary (``nodes``, ``rate``, ``tokens``) turns an executed attack into a
# false "PROTECTED", which is the most dangerous mistake this tool can make.
_LIMIT_PHRASES = _phrases(
    "depth", "complex", "cost", "exceed", "maximum", "too many", "too large",
    "too deep", "too long", "too much", "limit", "budget", "alias", "batch",
    "node count", "node limit", "token count", "token limit",
    "operation count", "not allowed", "disabled", "blocked", "rejected",
)

# Spec rule "Directives Are Unique Per Location". A server quoting this has
# refused the document for being invalid GraphQL, not for its directive count.
_DUPLICATE_DIRECTIVE_PHRASES = _phrases(
    "can only be used once", "duplicate directive", "non-repeatable",
    "not repeatable", "unique per location", "more than once",
)


def _rejection_text(resp: "GraphQLResponse") -> str:
    """The text that may carry a rejection reason.

    GraphQL ``errors`` messages when present. Otherwise the raw body, but only
    for a non-2xx response, so a proxy/WAF page is still recognised while a
    *successful* body never is: field and type names such as ``nodes`` or
    ``rateLimit`` are ordinary data, not evidence of a protective limit.
    """
    messages = [str(e.get("message", "")) for e in resp.graphql_errors]
    if messages:
        return " ".join(messages)
    if resp.status_code is None or not resp.ok:
        return resp.text
    return ""


def classify_rejection(resp: "GraphQLResponse") -> Rejection:
    """Why — if at all — the server refused this probe."""
    status = resp.status_code
    if status in (413, 414, 431):
        return Rejection.SIZE
    if status == 429:
        return Rejection.RATE
    if status in (401, 407):
        return Rejection.AUTH

    text = _rejection_text(resp)
    if text:
        if _AUTH_PHRASES.search(text):
            return Rejection.AUTH
        if _RATE_PHRASES.search(text):
            return Rejection.RATE
        if _SIZE_PHRASES.search(text):
            return Rejection.SIZE
        if _LIMIT_PHRASES.search(text):
            return Rejection.LIMIT

    if status == 403:
        return Rejection.AUTH
    if resp.graphql_errors and not resp.has_data:
        return Rejection.VALIDATION
    if status is not None and 400 <= status < 500:
        return Rejection.VALIDATION
    return Rejection.NONE


def rejected_as_duplicate_directive(resp: "GraphQLResponse") -> bool:
    """True if the document was refused for repeating a non-repeatable directive.

    That is the spec's "Directives Are Unique Per Location" rule firing, not a
    directive-*count* limit, so it says nothing about the endpoint's resilience
    to directive overloading.
    """
    if resp.has_data:
        return False
    return bool(_DUPLICATE_DIRECTIVE_PHRASES.search(_rejection_text(resp)))


def response_indicates_limit(resp: "GraphQLResponse") -> bool:
    """True if the response looks like a deliberate protective rejection.

    Convenience wrapper over :func:`classify_rejection`. Note that it is True
    for throttling too; callers that must tell a query limit apart from a rate
    limiter should use :func:`classify_rejection` directly.
    """
    return classify_rejection(resp) in (
        Rejection.LIMIT,
        Rejection.SIZE,
        Rejection.RATE,
    )


def endpoint_healthy(resp: "GraphQLResponse") -> bool:
    """True if a trivial control query came back normally."""
    return (
        resp.error is None
        and not resp.timed_out
        and resp.ok
        and not resp.graphql_errors
        and resp.has_data
    )


CONTROL_QUERY = "query GdosControl { __typename }"


class Check:
    """Base class for all resilience checks."""

    name: str = "base"
    vector: str = "generic"
    severity: Severity = Severity.MEDIUM
    remediation: str = ""

    def __init__(self, intensity: str = "medium", slow_factor: float = 3.0) -> None:
        self.intensity = intensity
        # A probe is considered to have a "resource impact" if it takes
        # ``slow_factor`` times the baseline (plus a small floor).
        self.slow_factor = slow_factor

    def run(self, client: "GraphQLClient", baseline: float) -> CheckResult:
        raise NotImplementedError

    # -- helpers shared by subclasses ------------------------------------

    def _scaled(self, low: int, medium: int, high: int) -> int:
        return {"low": low, "medium": medium, "high": high}.get(self.intensity, medium)

    def _is_slow(self, elapsed: float, baseline: float) -> bool:
        return elapsed >= max(baseline * self.slow_factor, baseline + 1.0)

    def _control(self, client: "GraphQLClient") -> "GraphQLResponse":
        """Send a trivial benign query to see what state the endpoint is in.

        Sent only after an outcome the probe alone cannot explain — a timeout,
        a 5xx, throttling, or an unexpected slowdown. It is what separates "the
        payload exhausted this server" from "this server/network is like that
        right now", and it costs nothing on a clean scan.
        """
        return client.query(CONTROL_QUERY)

    def _result(
        self,
        verdict: Verdict,
        summary: str,
        resp: "GraphQLResponse",
        baseline: float,
        evidence: dict[str, object] | None = None,
        severity: Severity | None = None,
        abort_scan: bool = False,
    ) -> CheckResult:
        ev: dict[str, object] = {
            "status_code": resp.status_code,
            "elapsed_seconds": round(resp.elapsed, 3),
        }
        if resp.timed_out:
            ev["timed_out"] = True
        if resp.error:
            ev["transport_error"] = resp.error
        if resp.graphql_errors:
            ev["graphql_errors"] = [
                str(e.get("message", ""))[:200] for e in resp.graphql_errors[:3]
            ]
        if evidence:
            ev.update(evidence)
        return CheckResult(
            name=self.name,
            vector=self.vector,
            verdict=verdict,
            severity=severity or self.severity,
            summary=summary,
            remediation=self.remediation,
            elapsed=resp.elapsed,
            baseline_elapsed=baseline,
            evidence=ev,
            abort_scan=abort_scan,
        )

    # -- shared verdict logic ---------------------------------------------

    def _unreachable(
        self, resp: "GraphQLResponse", baseline: float, what: str
    ) -> CheckResult:
        """The endpoint stopped answering even a trivial query.

        Either this probe took it down — which would be the finding — or it
        became unavailable for reasons of its own. A single bounded probe
        cannot tell those apart, so the honest answer is INCONCLUSIVE, and the
        scan stops rather than hammering an endpoint that may already be down.
        """
        return self._result(
            Verdict.INCONCLUSIVE,
            f"{what} and the endpoint no longer answers a trivial control query. "
            "It may have been taken down by this probe, or be unavailable for "
            "unrelated reasons — that cannot be attributed from a single probe. "
            "Scan aborted; confirm the endpoint is healthy before re-running.",
            resp,
            baseline,
            evidence={"control_probe": "unhealthy"},
            severity=Severity.MEDIUM,
            abort_scan=True,
        )

    def _auth_wall(
        self, resp: "GraphQLResponse", baseline: float, vector_label: str
    ) -> CheckResult:
        return self._result(
            Verdict.INCONCLUSIVE,
            f"Endpoint refused the {vector_label} probe for authentication/"
            "authorization reasons, so its DoS controls were never exercised. "
            "Re-run with credentials (--token / -H) that reach the schema.",
            resp,
            baseline,
            evidence={"rejection": Rejection.AUTH.value},
            severity=Severity.LOW,
        )

    def _throttled(
        self,
        client: "GraphQLClient",
        resp: "GraphQLResponse",
        baseline: float,
        vector_label: str,
    ) -> CheckResult:
        """A 429/throttle answer. Protective only if trivial queries still pass."""
        if endpoint_healthy(self._control(client)):
            return self._result(
                Verdict.PROTECTED,
                f"Server throttled the {vector_label} payload specifically while "
                "continuing to serve trivial queries — a cost- or complexity-aware "
                "rate limit is in effect.",
                resp,
                baseline,
                evidence={"rejection": Rejection.RATE.value, "control_probe": "healthy"},
                severity=Severity.INFO,
            )
        return self._result(
            Verdict.INCONCLUSIVE,
            "Endpoint is rate-limiting every request, including trivial ones. "
            "Remaining verdicts would reflect the throttle rather than the "
            "endpoint's DoS controls. Scan aborted; retry later or raise --delay.",
            resp,
            baseline,
            evidence={"rejection": Rejection.RATE.value, "control_probe": "throttled"},
            severity=Severity.LOW,
            abort_scan=True,
        )

    def _classify_amplification(
        self,
        client: "GraphQLClient",
        resp: "GraphQLResponse",
        baseline: float,
        vector_label: str,
    ) -> CheckResult:
        """Shared logic for amplification-style probes (alias/batch/depth/...).

        The probe is an abusive payload that a hardened server should refuse.
        """
        if resp.error and not resp.timed_out:
            return self._result(
                Verdict.ERROR,
                f"Probe could not be delivered: {resp.error}",
                resp,
                baseline,
                severity=Severity.INFO,
            )

        if resp.timed_out:
            if endpoint_healthy(self._control(client)):
                return self._result(
                    Verdict.VULNERABLE,
                    f"Server did not respond within the timeout for the "
                    f"{vector_label} probe, yet still answers a trivial query — "
                    "the payload specifically exhausted it and no upfront limit "
                    "rejected it.",
                    resp,
                    baseline,
                    evidence={"control_probe": "healthy"},
                )
            return self._unreachable(
                resp, baseline, f"The {vector_label} probe timed out"
            )

        if resp.status_code is not None and resp.status_code >= 500:
            if endpoint_healthy(self._control(client)):
                return self._result(
                    Verdict.VULNERABLE,
                    f"Server returned {resp.status_code} on the {vector_label} "
                    "probe while still serving trivial queries — the abusive "
                    "payload reached execution and crashed/erred the server.",
                    resp,
                    baseline,
                    evidence={"control_probe": "healthy"},
                )
            return self._unreachable(
                resp, baseline, f"The {vector_label} probe returned {resp.status_code}"
            )

        rejection = classify_rejection(resp)

        if rejection is Rejection.AUTH:
            return self._auth_wall(resp, baseline, vector_label)

        if rejection is Rejection.RATE:
            return self._throttled(client, resp, baseline, vector_label)

        # A refusal that was expensive to produce is still a resource finding.
        # A parser or validator that burns CPU on the payload before saying no
        # can be driven just as hard as one that executes it (CVE-2022-37734),
        # so the slowdown check runs ahead of the verdict rather than only on
        # the path where data came back.
        if self._is_slow(resp.elapsed, baseline):
            control = self._control(client)
            if not endpoint_healthy(control):
                # The endpoint has just stopped answering even trivial queries.
                # Every other path treats that as a reason to stop; a slow
                # probe is no exception, and continuing would fire the
                # remaining payloads at a target that is already unwell.
                return self._unreachable(
                    resp, baseline, f"The {vector_label} probe was slow"
                )
            if not self._is_slow(control.elapsed, baseline):
                # Absolute timings, not a ratio: against a sub-millisecond
                # baseline a ratio reads as a meaningless four-digit number.
                timing = (
                    f"{resp.elapsed:.2f}s against a {baseline:.3f}s baseline"
                )
                if resp.ok and resp.has_data:
                    summary = (
                        f"Server accepted and processed the {vector_label} "
                        f"payload, taking {timing}, while trivial queries stayed "
                        "fast — no effective upfront limit."
                    )
                else:
                    summary = (
                        f"Server refused the {vector_label} payload but took "
                        f"{timing} to do it, while trivial queries stayed fast — "
                        "the work happens before the rejection, so the payload "
                        "still consumes resources."
                    )
                return self._result(
                    Verdict.VULNERABLE,
                    summary,
                    resp,
                    baseline,
                    evidence={
                        "control_probe": "healthy",
                        "control_elapsed_seconds": round(control.elapsed, 3),
                        "rejection": rejection.value,
                    },
                )
            return self._result(
                Verdict.INCONCLUSIVE,
                f"The {vector_label} probe was slow, but a trivial control query "
                "is slow too — the endpoint or network is degraded, so the "
                "slowdown cannot be attributed to the payload.",
                resp,
                baseline,
                evidence={
                    "control_probe": "degraded",
                    "control_elapsed_seconds": round(control.elapsed, 3),
                },
                severity=Severity.LOW,
            )

        if rejection in (Rejection.LIMIT, Rejection.SIZE) and not resp.has_data:
            detail = (
                "a protective limit/validation error"
                if rejection is Rejection.LIMIT
                else f"a raw request-size limit (HTTP {resp.status_code})"
            )
            return self._result(
                Verdict.PROTECTED,
                f"Server rejected the {vector_label} payload with {detail}.",
                resp,
                baseline,
                evidence={"rejection": rejection.value},
                severity=Severity.INFO,
            )

        if resp.ok and resp.has_data:
            if rejection in (Rejection.LIMIT, Rejection.SIZE):
                return self._result(
                    Verdict.INCONCLUSIVE,
                    f"Server returned data for the {vector_label} probe *and* a "
                    "limit error — it may be truncating rather than rejecting. "
                    "Manual review recommended.",
                    resp,
                    baseline,
                    evidence={"rejection": rejection.value},
                    severity=Severity.LOW,
                )
            return self._result(
                Verdict.VULNERABLE,
                f"Server executed the {vector_label} payload and returned data. "
                "No depth/complexity/amount limit appears to be enforced; the "
                "payload can be scaled up to exhaust resources.",
                resp,
                baseline,
            )

        if rejection is Rejection.VALIDATION:
            return self._result(
                Verdict.PROTECTED,
                f"Server rejected the {vector_label} payload during validation, "
                "before execution, though it did not name a specific limit.",
                resp,
                baseline,
                evidence={"rejection": rejection.value},
                severity=Severity.INFO,
            )

        return self._result(
            Verdict.INCONCLUSIVE,
            f"Unexpected response to the {vector_label} probe "
            f"(status {resp.status_code}, no data and no errors); manual review "
            "recommended.",
            resp,
            baseline,
            severity=Severity.LOW,
        )
