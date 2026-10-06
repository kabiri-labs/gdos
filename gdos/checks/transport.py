"""Checks on how the endpoint is reached, and on what it volunteers.

These three do not amplify anything by themselves. They cover the surface that
makes amplification practical: a transport that the deployment's limits do not
cover, a delivery mode that turns one request into a stream of many, and error
messages that hand an attacker the schema needed to aim a complexity attack.
"""

from __future__ import annotations

from gdos.checks.base import (
    Check,
    CheckResult,
    Rejection,
    Severity,
    Verdict,
    classify_rejection,
    endpoint_healthy,
)
from gdos.client import GraphQLClient

_SUGGESTION_PROBE = "query GdosSuggestionProbe { __typenam }"
"""A near-miss of ``__typename``, which exists on every GraphQL server, so the
suggestion machinery can be observed without knowing anything about the schema.
"""

_SUGGESTION_MARKERS = ("did you mean", "perhaps you meant", "didyoumean")


class FieldSuggestionCheck(Check):
    """Whether validation errors volunteer the names of real fields.

    "Did you mean …?" lets an attacker reconstruct a schema field by field even
    when introspection is disabled, which is what makes the usual advice — turn
    introspection off — worth far less than it looks. The reconstructed schema
    is then what a targeted complexity attack is aimed with.
    """

    name = "field-suggestions"
    vector = "Field suggestion leakage"
    severity = Severity.MEDIUM
    remediation = (
        "Strip field suggestions from client-facing errors in production "
        "(GraphQL-JS: `NoDeprecatedCustomRule`-style error masking, envelop's "
        "`useMaskedErrors`, or Apollo's `formatError`). Disabling introspection "
        "while leaving suggestions on still exposes the schema."
    )

    def run(self, client: GraphQLClient, baseline: float) -> CheckResult:
        resp = client.query(_SUGGESTION_PROBE)

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
                    Verdict.INCONCLUSIVE,
                    "The field-suggestion probe timed out while trivial queries "
                    "still succeed; suggestion behaviour is unknown.",
                    resp,
                    baseline,
                    severity=Severity.LOW,
                )
            return self._unreachable(
                resp, baseline, "The field-suggestion probe timed out"
            )

        rejection = classify_rejection(resp)
        if rejection is Rejection.AUTH:
            return self._auth_wall(resp, baseline, "field suggestion")
        if rejection is Rejection.RATE:
            return self._throttled(client, resp, baseline, "field suggestion")

        messages = resp.error_messages()
        if any(marker in messages for marker in _SUGGESTION_MARKERS):
            return self._result(
                Verdict.VULNERABLE,
                "Server suggests real field names in validation errors — the "
                "schema can be reconstructed field by field without "
                "introspection, and targeted complexity attacks aimed with it.",
                resp,
                baseline,
                evidence={"suggestions": True},
            )

        if resp.graphql_errors:
            return self._result(
                Verdict.PROTECTED,
                "Server rejected an unknown field without naming a real one — "
                "errors do not leak schema contents.",
                resp,
                baseline,
                evidence={"suggestions": False},
                severity=Severity.INFO,
            )

        return self._result(
            Verdict.INCONCLUSIVE,
            "Server returned no validation error for an unknown field "
            f"(status {resp.status_code}); suggestion behaviour is unknown.",
            resp,
            baseline,
            severity=Severity.LOW,
        )


class GetMethodCheck(Check):
    """Whether queries execute over GET as well as POST.

    A deployment's protections are often attached to POST: a WAF rule on the
    request body, a body-size cap, a rate limit keyed on the POST route. If the
    same documents execute over GET, every one of those is optional from the
    attacker's side, and the response may additionally be cacheable by
    intermediaries.

    The probe is deliberately small. What is under test is the endpoint's
    policy, not how long a URL it will take.
    """

    name = "get-method"
    vector = "Query execution over GET"
    severity = Severity.MEDIUM
    remediation = (
        "Accept queries only over POST, or make sure every depth, complexity, "
        "size and rate control applies to GET identically. Mutations must "
        "never be reachable over GET."
    )

    _ALIAS_COUNT = 100
    """Fixed, and small: ~2 KB of URL. Raising it would test URL length limits
    instead of the policy question, and could trip an intermediary rather than
    the endpoint."""

    def run(self, client: GraphQLClient, baseline: float) -> CheckResult:
        aliases = " ".join(f"g{i}: __typename" for i in range(self._ALIAS_COUNT))
        resp = client.get("query GdosGetProbe { %s }" % aliases)
        evidence: dict[str, object] = {"alias_count": self._ALIAS_COUNT}

        if resp.error and not resp.timed_out:
            return self._result(
                Verdict.ERROR,
                f"Probe could not be delivered: {resp.error}",
                resp,
                baseline,
                evidence=evidence,
                severity=Severity.INFO,
            )
        if resp.timed_out:
            if endpoint_healthy(self._control(client)):
                return self._result(
                    Verdict.VULNERABLE,
                    "A GET query timed out while trivial POST queries still "
                    "succeed — GET reaches execution and is not bounded.",
                    resp,
                    baseline,
                    evidence=evidence,
                )
            return self._unreachable(resp, baseline, "The GET probe timed out")

        # 405 is the clean answer, and a size limit on the URL is also a limit.
        if resp.status_code in (405, 404, 501):
            return self._result(
                Verdict.PROTECTED,
                f"Server refused the GET request outright (HTTP "
                f"{resp.status_code}) — queries are POST-only.",
                resp,
                baseline,
                evidence=evidence,
                severity=Severity.INFO,
            )

        rejection = classify_rejection(resp)
        if rejection is Rejection.AUTH:
            return self._auth_wall(resp, baseline, "GET query")
        if rejection is Rejection.RATE:
            return self._throttled(client, resp, baseline, "GET query")
        if rejection in (Rejection.LIMIT, Rejection.SIZE) and not resp.has_data:
            return self._result(
                Verdict.PROTECTED,
                "Server rejected the GET query with a limit or size error — "
                "GET is covered by the same controls as POST.",
                resp,
                baseline,
                evidence=evidence,
                severity=Severity.INFO,
            )

        if resp.ok and resp.has_data:
            resolved = len(resp.data or {})
            evidence["aliases_resolved"] = resolved
            return self._result(
                Verdict.VULNERABLE,
                f"Server executed a {self._ALIAS_COUNT}-alias query sent in the "
                f"URL and resolved {resolved} of them. Controls attached to "
                "POST — body-size caps, WAF body rules, route-scoped rate "
                "limits — do not apply on this path, and the response may be "
                "cached by intermediaries.",
                resp,
                baseline,
                evidence=evidence,
            )

        if rejection is Rejection.VALIDATION:
            return self._result(
                Verdict.PROTECTED,
                "Server rejected the GET query before execution.",
                resp,
                baseline,
                evidence=evidence,
                severity=Severity.INFO,
            )

        return self._result(
            Verdict.INCONCLUSIVE,
            f"Unexpected response to the GET probe (status {resp.status_code}).",
            resp,
            baseline,
            evidence=evidence,
            severity=Severity.LOW,
        )


class IncrementalDeliveryCheck(Check):
    """Many ``@defer`` fragments in one document (incremental delivery).

    ``@defer`` turns a single request into a stream of payloads, each of which
    the server must keep state for until it is delivered. The defer/stream RFC
    names an unbounded number of ``@defer`` directives as an open
    denial-of-service question, and a server that implements the directives
    without capping them answers one small request with as many payloads as the
    client asked for.

    A server that does *not* implement incremental delivery must fail the
    document in validation, which is the correct and expected outcome for most
    endpoints today.
    """

    name = "incremental-delivery"
    vector = "Incremental delivery overload (@defer)"
    severity = Severity.MEDIUM
    remediation = (
        "If incremental delivery is enabled, cap the number of @defer/@stream "
        "directives per document and count them in the complexity budget. If "
        "it is not needed, leave the directives out of the schema so documents "
        "using them fail validation."
    )

    def _build(self, count: int) -> str:
        # Unique labels: the spec requires defer labels to be distinct, so a
        # repeated label would be refused for being invalid rather than for
        # being excessive — the same trap the directive check documents.
        fragments = " ".join(
            '... @defer(label: "gdos%d") { name kind }' % i for i in range(count)
        )
        return 'query GdosDeferProbe { __type(name: "String") { %s } }' % fragments

    def run(self, client: GraphQLClient, baseline: float) -> CheckResult:
        count = self._scaled(low=50, medium=250, high=1000)
        resp = client.query(self._build(count))
        evidence: dict[str, object] = {"defer_count": count}

        # An incremental response is a multipart stream, not a JSON document,
        # so it will not parse. The stream arriving at all is the observation.
        if resp.is_multipart:
            result = self._result(
                Verdict.VULNERABLE,
                f"Server accepted {count} @defer directives in one document and "
                "began streaming incremental payloads — each one is state the "
                "server holds for a single small request, and nothing capped "
                "how many were asked for.",
                resp,
                baseline,
                evidence=evidence,
            )
            result.evidence["content_type"] = resp.content_type
            return result

        result = self._classify_amplification(
            client, resp, baseline, "incremental delivery"
        )
        result.evidence.update(evidence)
        return result
