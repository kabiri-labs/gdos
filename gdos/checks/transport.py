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

    Executing a query over GET is not itself a defect — the
    GraphQL-over-HTTP specification permits it for query operations, and plenty
    of hardened deployments allow it. The finding is *asymmetry*. So the same
    document is sent over both transports and the answers compared: only a GET
    that succeeds where POST was refused shows that a control was bypassed by
    changing transport.

    The probe is deliberately small. What is under test is the endpoint's
    policy, not how long a URL it will take.
    """

    name = "get-method"
    vector = "Transport asymmetry (GET)"
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
        document = "query GdosGetProbe { %s }" % aliases
        resp = client.get(document)
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

        # Redirects are deliberately not followed for this probe, so a 3xx is
        # an answer about a different location than the one under test.
        if resp.status_code is not None and 300 <= resp.status_code < 400:
            return self._result(
                Verdict.INCONCLUSIVE,
                f"Endpoint answered the GET probe with HTTP {resp.status_code}. "
                "GDoS does not follow it here, because the policy at the "
                "redirect target is not the policy under test — re-run "
                "against the final URL.",
                resp,
                baseline,
                evidence=evidence,
                severity=Severity.LOW,
            )

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
                "Server rejected the GET query with a limit or size error, so "
                "GET is covered by controls of its own.",
                resp,
                baseline,
                evidence=evidence,
                severity=Severity.INFO,
            )

        if resp.ok and resp.has_data:
            evidence["get_executed"] = True
            evidence["aliases_resolved"] = len(resp.data or {})
            return self._compare_with_post(client, resp, baseline, document, evidence)

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

    def _compare_with_post(
        self,
        client: GraphQLClient,
        resp,
        baseline: float,
        document: str,
        evidence: dict[str, object],
    ) -> CheckResult:
        """GET executed. Did POST refuse the identical document?

        This is the comparison that separates "this endpoint serves GraphQL
        over GET", which the specification allows, from "this endpoint's
        controls can be stepped around by moving the query into the URL".
        """
        post = client.query(document)
        evidence["post_status"] = post.status_code

        if post.error or post.timed_out:
            return self._result(
                Verdict.INCONCLUSIVE,
                "The GET query executed, but the identical document could not "
                f"be delivered over POST ({post.error or 'timed out'}), so the "
                "two transports could not be compared.",
                resp,
                baseline,
                evidence=evidence,
                severity=Severity.LOW,
            )

        post_rejection = classify_rejection(post)
        if post_rejection in (Rejection.AUTH, Rejection.RATE):
            return self._result(
                Verdict.INCONCLUSIVE,
                "The GET query executed, but POST answered the identical "
                f"document with a {post_rejection.value} refusal, so the two "
                "transports could not be compared on equal terms.",
                resp,
                baseline,
                evidence=evidence,
                severity=Severity.LOW,
            )

        post_executed = post.ok and post.has_data
        evidence["post_executed"] = post_executed

        if post_executed:
            return self._result(
                Verdict.PROTECTED,
                "Server executes queries over GET, which GraphQL-over-HTTP "
                "permits, and answers the identical document over POST the "
                "same way — no control is bypassed by changing transport. "
                "Whether any alias or complexity limit exists at all is a "
                "separate question, answered by the alias-overloading check.",
                resp,
                baseline,
                evidence=evidence,
                severity=Severity.INFO,
            )

        return self._result(
            Verdict.VULNERABLE,
            f"POST refused the identical document (HTTP {post.status_code}, "
            f"{post_rejection.value}) but GET executed it and resolved "
            f"{evidence.get('aliases_resolved')} of {self._ALIAS_COUNT} "
            "aliases. The deployment's controls are attached to POST and are "
            "bypassed by moving the query into the URL — body-size caps, "
            "WAF body rules and route-scoped rate limits all apply to one "
            "transport only, and the GET response may additionally be cached "
            "by intermediaries.",
            resp,
            baseline,
            evidence=evidence,
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

    _ACCEPT = "multipart/mixed; deferSpec=20220824, application/json"
    """Incremental delivery is content-negotiated. A server that is asked for
    ``application/json`` alone may correctly refuse to stream, so a probe that
    does not advertise the multipart type cannot observe @defer support at
    all."""

    def run(self, client: GraphQLClient, baseline: float) -> CheckResult:
        count = self._scaled(low=50, medium=250, high=1000)
        resp = client.query(self._build(count), accept=self._ACCEPT)
        evidence: dict[str, object] = {"defer_count": count, "accept": self._ACCEPT}

        # Asked for the incremental media type and told no: this server does
        # not do incremental delivery, which is the hardened answer.
        if resp.status_code == 406:
            return self._result(
                Verdict.PROTECTED,
                "Server cannot produce an incremental-delivery response (HTTP "
                "406) even when one is requested, so @defer is not a usable "
                "vector against it.",
                resp,
                baseline,
                evidence=evidence,
                severity=Severity.INFO,
            )

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
