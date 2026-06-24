"""Base types shared by every resilience check.

A *check* probes a single GraphQL DoS vector with one bounded request and
classifies the endpoint's behaviour. Checks are read-only with respect to the
target: they never loop, never escalate automatically, and always honour the
client timeout.
"""

from __future__ import annotations

import enum
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
    """Could not determine — e.g. auth required, unexpected response shape."""
    ERROR = "ERROR"
    """The probe itself failed (network error, unreachable endpoint)."""


class Severity(enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


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


# Keywords that, when present in a GraphQL error message, strongly indicate the
# server enforced a protective limit rather than simply failing to resolve data.
_LIMIT_KEYWORDS: tuple[str, ...] = (
    "depth",
    "complex",
    "cost",
    "exceed",
    "exceeds",
    "maximum",
    "too many",
    "too large",
    "too deep",
    "limit",
    "limited",
    "not allowed",
    "disabled",
    "rejected",
    "aliases",
    "tokens",
    "nodes",
    "rate",
    "throttle",
)


def response_indicates_limit(resp: "GraphQLResponse") -> bool:
    """True if the response looks like a deliberate protective rejection."""
    if resp.status_code in (400, 403, 422, 429):
        # A clear client-side rejection. 400 with a validation error is the
        # canonical "query rejected by depth/complexity rule" signal.
        if resp.status_code == 429:
            return True
        msg = resp.error_messages()
        if any(k in msg for k in _LIMIT_KEYWORDS):
            return True
        # A 400 with GraphQL errors and no returned data is still a rejection.
        if resp.graphql_errors and not resp.has_data:
            return True
    msg = resp.error_messages()
    return bool(msg) and any(k in msg for k in _LIMIT_KEYWORDS)


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

    def _result(
        self,
        verdict: Verdict,
        summary: str,
        resp: "GraphQLResponse",
        baseline: float,
        evidence: dict[str, object] | None = None,
        severity: Severity | None = None,
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
        )

    def _classify_amplification(
        self, resp: "GraphQLResponse", baseline: float, vector_label: str
    ) -> CheckResult:
        """Shared logic for amplification-style probes (alias/batch/depth/...).

        The probe is an abusive payload that a hardened server should refuse. We
        map the observed behaviour to a verdict.
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
            return self._result(
                Verdict.VULNERABLE,
                f"Server did not respond within the timeout for the {vector_label} "
                "probe — strong sign of resource exhaustion and no upfront limit.",
                resp,
                baseline,
            )
        if response_indicates_limit(resp):
            return self._result(
                Verdict.PROTECTED,
                f"Server rejected the {vector_label} payload with a protective "
                "limit/validation error.",
                resp,
                baseline,
                severity=Severity.INFO,
            )
        if resp.status_code is not None and resp.status_code >= 500:
            return self._result(
                Verdict.VULNERABLE,
                f"Server returned {resp.status_code} on the {vector_label} probe — "
                "the abusive payload reached execution and crashed/erred the server.",
                resp,
                baseline,
            )
        if self._is_slow(resp.elapsed, baseline):
            return self._result(
                Verdict.VULNERABLE,
                f"Server accepted and processed the {vector_label} payload and was "
                f"{resp.elapsed / max(baseline, 1e-3):.1f}x slower than baseline — "
                "no effective upfront limit.",
                resp,
                baseline,
            )
        if resp.ok:
            return self._result(
                Verdict.VULNERABLE,
                f"Server accepted the {vector_label} payload without rejecting it. "
                "No depth/complexity/amount limit appears to be enforced; the "
                "payload can be scaled up to exhaust resources.",
                resp,
                baseline,
            )
        return self._result(
            Verdict.INCONCLUSIVE,
            f"Unexpected response to the {vector_label} probe "
            f"(status {resp.status_code}); manual review recommended.",
            resp,
            baseline,
            severity=Severity.LOW,
        )
