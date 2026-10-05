"""Unit tests for the resilience checks and verdict classification.

These tests exercise the decision logic with a fake client, so no network
access (and no live GraphQL server) is required.
"""

from __future__ import annotations

import pytest

from gdos.checks import (
    ALL_CHECKS,
    AliasOverloadingCheck,
    BatchingCheck,
    CircularFragmentCheck,
    DeepIntrospectionCheck,
    DirectiveOverloadingCheck,
    IntrospectionEnabledCheck,
    QueryDepthCheck,
)
from gdos.checks.base import (
    CONTROL_QUERY,
    Rejection,
    Verdict,
    classify_rejection,
    response_indicates_limit,
)
from gdos.cli import exit_code
from gdos.client import GraphQLResponse
from gdos.reporting import to_json, to_text
from gdos.scanner import ScanReport, Scanner


class FakeClient:
    """A GraphQLClient stand-in that replays queued responses.

    Responses are consumed in order and the last one repeats, so a test can
    script "abusive probe answers X, the control probe that follows answers Y"
    without caring how many control probes a check decides to send.
    """

    url = "http://example.test/graphql"

    def __init__(self, *responses: GraphQLResponse) -> None:
        self._responses = list(responses) or [gql()]
        self.queries: list[str] = []
        self.payloads: list[object] = []

    @property
    def last_query(self) -> str | None:
        return self.queries[-1] if self.queries else None

    def _next(self) -> GraphQLResponse:
        if len(self._responses) > 1:
            return self._responses.pop(0)
        return self._responses[0]

    def query(self, query: str, variables=None) -> GraphQLResponse:
        self.queries.append(query)
        return self._next()

    def post(self, payload) -> GraphQLResponse:
        self.payloads.append(payload)
        return self._next()


def gql(json=None, status=200, elapsed=0.05, **kw) -> GraphQLResponse:
    return GraphQLResponse(status_code=status, elapsed=elapsed, json=json, **kw)


def healthy(elapsed: float = 0.05) -> GraphQLResponse:
    """What a trivial control query looks like on a well endpoint."""
    return gql(json={"data": {"__typename": "Query"}}, elapsed=elapsed)


def timed_out(elapsed: float = 15.0) -> GraphQLResponse:
    return GraphQLResponse(
        status_code=None, elapsed=elapsed, timed_out=True, error="request timed out"
    )


# --- classify_rejection ------------------------------------------------------

@pytest.mark.parametrize(
    "resp",
    [
        gql(status=400, json={"errors": [{"message": "Query depth 12 exceeds maximum of 5"}]}),
        gql(status=200, json={"errors": [{"message": "Query is too complex"}]}),
        gql(status=429, json={"errors": [{"message": "rate limited"}]}),
        gql(status=403, json={"errors": [{"message": "too many aliases"}]}),
    ],
)
def test_limit_detected(resp):
    assert response_indicates_limit(resp) is True


@pytest.mark.parametrize(
    "resp",
    [
        gql(status=200, json={"data": {"__typename": "Query"}}),
        gql(status=200, json={"errors": [{"message": "Cannot query field 'foo'"}]}),
    ],
)
def test_limit_not_detected(resp):
    assert response_indicates_limit(resp) is False


@pytest.mark.parametrize(
    "resp, expected",
    [
        (gql(status=401), Rejection.AUTH),
        (gql(status=403, json={"errors": [{"message": "nope"}]}), Rejection.AUTH),
        (gql(status=200, json={"errors": [{"message": "Unauthorized"}]}), Rejection.AUTH),
        (gql(status=200, json={"errors": [{"message": "You must be logged in"}]}), Rejection.AUTH),
        (gql(status=429), Rejection.RATE),
        (gql(status=200, json={"errors": [{"message": "Too Many Requests"}]}), Rejection.RATE),
        (gql(status=413), Rejection.SIZE),
        (gql(status=400, json={"errors": [{"message": "max depth exceeded"}]}), Rejection.LIMIT),
        (gql(status=200, json={"errors": [{"message": "Cannot query field 'x'"}]}), Rejection.VALIDATION),
        (gql(status=200, json={"data": {"__typename": "Query"}}), Rejection.NONE),
    ],
)
def test_rejection_classification(resp, expected):
    assert classify_rejection(resp) is expected


@pytest.mark.parametrize(
    "message",
    [
        "You are not authorized to access this resource",
        "The current user is not authorised",
        "Authentication required",
        "This endpoint requires authentication",
        "You are not allowed to access field 'secret'",
        "You have no permission to run this query",
    ],
)
def test_spaced_authorization_failures_are_auth(message):
    """Regression: a word-boundary match on `unauthorized` misses `not authorized`.

    Such a message used to fall through to VALIDATION, which amplification
    checks read as PROTECTED — recreating the false-clean auth result.
    """
    resp = gql(json={"errors": [{"message": message}], "data": None})
    assert classify_rejection(resp) is Rejection.AUTH


def test_not_allowed_without_access_is_still_a_limit():
    """The narrow auth phrase must not swallow genuine limit messages."""
    resp = gql(
        status=400, json={"errors": [{"message": "Batching is not allowed"}]}
    )
    assert classify_rejection(resp) is Rejection.LIMIT


def test_spaced_auth_failure_is_inconclusive_not_protected():
    resp = gql(
        json={"errors": [{"message": "You are not authorized to access this"}],
              "data": None}
    )
    result = QueryDepthCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.INCONCLUSIVE


def test_auth_rejection_outranks_limit_vocabulary():
    """An auth wall saying "not allowed" must not read as a DoS control."""
    resp = gql(status=200, json={"errors": [{"message": "Access denied: not allowed"}]})
    assert classify_rejection(resp) is Rejection.AUTH


def test_successful_body_is_never_keyword_matched():
    """Regression: schema/data vocabulary is not evidence of a limit.

    A served response whose body happens to contain words like ``nodes``,
    ``rateLimit`` or ``maximum`` used to be read as a protective rejection,
    turning a fully executed amplification into a false PROTECTED.
    """
    resp = gql(
        json={"data": {"viewer": {"rateLimit": {"limit": 5000}, "nodes": []}}},
    )
    assert classify_rejection(resp) is Rejection.NONE
    assert response_indicates_limit(resp) is False


def test_non_2xx_body_without_graphql_errors_is_still_matched():
    """A proxy/WAF page carries no GraphQL errors but is still a rejection."""
    resp = GraphQLResponse(
        status_code=400, elapsed=0.1, text="Request blocked: query too deep"
    )
    assert classify_rejection(resp) is Rejection.LIMIT


# --- amplification classification --------------------------------------------

def _alias_data(n: int) -> dict:
    return {"data": {f"a{i}": "Query" for i in range(n)}}


def test_alias_protected_when_rejected():
    resp = gql(status=400, json={"errors": [{"message": "max alias count exceeded"}]})
    result = AliasOverloadingCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.PROTECTED


def test_alias_vulnerable_when_fully_executed():
    check = AliasOverloadingCheck()
    count = check._scaled(low=200, medium=1000, high=5000)
    result = check.run(FakeClient(gql(json=_alias_data(count))), baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE
    assert result.evidence["alias_count"] == count
    assert result.evidence["aliases_resolved"] == count


def test_alias_truncated_is_inconclusive_not_vulnerable():
    """Fewer aliases resolved than requested means capping, not execution."""
    check = AliasOverloadingCheck()
    count = check._scaled(low=200, medium=1000, high=5000)
    result = check.run(FakeClient(gql(json=_alias_data(10))), baseline=0.05)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.evidence["aliases_resolved"] == 10
    assert result.evidence["alias_count"] == count


def test_executed_payload_with_schema_vocabulary_is_vulnerable():
    """Regression: a real amplification must not be excused by its own output.

    The deep-introspection response lists every field name in the schema. When
    one of them is ``nodes`` or ``rateLimit``, the old keyword matcher read the
    served body as a protective rejection and reported PROTECTED.
    """
    body = {
        "data": {
            "__schema": {
                "types": [
                    {"name": "Repo", "fields": [{"name": "nodes"}, {"name": "rateLimit"}]}
                ]
            }
        }
    }
    result = DeepIntrospectionCheck().run(FakeClient(gql(json=body)), baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE


def test_http_200_with_errors_and_no_data_is_not_vulnerable():
    """Regression: 200 + validation errors is a rejection, not an execution.

    Servers such as graphql-yoga answer validation failures with HTTP 200. The
    old classifier saw ``resp.ok`` and reported VULNERABLE.
    """
    resp = gql(json={"errors": [{"message": "Cannot query field 'zzz'"}], "data": None})
    result = QueryDepthCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.PROTECTED


def test_auth_wall_is_inconclusive_not_protected():
    """Regression: an endpoint that refuses everything is not a hardened one."""
    resp = gql(status=401, json={"errors": [{"message": "Unauthorized"}]})
    result = AliasOverloadingCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.abort_scan is False


def test_error_on_transport_failure():
    resp = GraphQLResponse(status_code=None, elapsed=0.1, error="connection refused")
    result = AliasOverloadingCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.ERROR


# --- control probe -----------------------------------------------------------

def test_timeout_with_healthy_control_is_vulnerable():
    client = FakeClient(timed_out(), healthy())
    result = QueryDepthCheck().run(client, baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE
    assert result.evidence["control_probe"] == "healthy"
    assert client.queries[-1] == CONTROL_QUERY


def test_timeout_with_dead_control_is_inconclusive_and_aborts():
    """A dead endpoint must not be recorded as eight separate vulnerabilities."""
    result = QueryDepthCheck().run(FakeClient(timed_out(), timed_out()), baseline=0.05)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.abort_scan is True


def test_slow_probe_with_fast_control_is_vulnerable():
    probe = gql(json={"data": {"__type": {"name": "String"}}}, elapsed=5.0)
    result = QueryDepthCheck().run(FakeClient(probe, healthy(0.05)), baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE


def test_slow_probe_with_slow_control_is_inconclusive():
    """Endpoint-wide degradation is not attributable to the payload.

    The endpoint is still answering, so the scan carries on.
    """
    probe = gql(json={"data": {"__type": {"name": "String"}}}, elapsed=5.0)
    result = QueryDepthCheck().run(FakeClient(probe, healthy(6.0)), baseline=0.05)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.evidence["control_probe"] == "degraded"
    assert result.abort_scan is False


def test_slow_probe_with_dead_control_aborts():
    """Regression: a slow probe whose control dies must stop the scan.

    Every other path aborts when the control query fails. This one used to
    return INCONCLUSIVE and let the scanner keep firing abusive payloads at an
    endpoint that had just stopped responding.
    """
    probe = gql(json={"data": {"__type": {"name": "String"}}}, elapsed=5.0)
    result = QueryDepthCheck().run(FakeClient(probe, timed_out()), baseline=0.05)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.abort_scan is True


def test_server_error_with_healthy_control_is_vulnerable():
    result = QueryDepthCheck().run(
        FakeClient(gql(status=500, json=None), healthy()), baseline=0.05
    )
    assert result.verdict is Verdict.VULNERABLE


def test_throttled_probe_with_healthy_control_is_protected():
    result = AliasOverloadingCheck().run(
        FakeClient(gql(status=429), healthy()), baseline=0.05
    )
    assert result.verdict is Verdict.PROTECTED


def test_endpoint_wide_throttling_is_inconclusive_and_aborts():
    """Regression: a scan-induced 429 must not make every later check PROTECTED."""
    result = AliasOverloadingCheck().run(
        FakeClient(gql(status=429), gql(status=429)), baseline=0.05
    )
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.abort_scan is True


# --- directives --------------------------------------------------------------

_DUPLICATE_DIRECTIVE = gql(
    status=400,
    json={"errors": [{"message": "The directive 'skip' can only be used once at this location."}]},
)


def test_directive_executed_is_vulnerable():
    resp = gql(json={"data": {"__typename": "Query"}})
    check = DirectiveOverloadingCheck()
    client = FakeClient(resp)
    result = check.run(client, baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE
    assert result.evidence["directive_shape"] == "repeated-builtin"
    # The first shape settled it, so no fallback probe was needed.
    assert len(client.queries) == 1


def test_duplicate_directive_rejection_falls_back_to_unknown_names():
    """The uniqueness rule pre-empts the count limit, so try the other shape.

    CVE-2022-37734 used thousands of *distinct non-existent* directives, which
    the spec's uniqueness rule cannot refuse early. Without this fallback the
    check reports nothing useful against any compliant validator.
    """
    executed = gql(json={"data": {"__typename": "Query"}})
    client = FakeClient(_DUPLICATE_DIRECTIVE, executed)
    result = DirectiveOverloadingCheck().run(client, baseline=0.05)

    assert result.verdict is Verdict.VULNERABLE
    assert result.evidence["directive_shape"] == "distinct-unknown"
    assert result.evidence["repeated_shape_rejected_as_duplicate"] is True
    assert len(client.queries) == 2
    # The fallback must carry distinct names, or the uniqueness rule refuses
    # it for the same reason the first probe was refused.
    fallback = client.queries[1]
    assert "@gdosDir0" in fallback and "@gdosDir1" in fallback
    assert "@skip" not in fallback and "@include" not in fallback


def test_unknown_directives_refused_slowly_are_vulnerable():
    """CVE-2022-37734 is CPU burned during validation, before the rejection."""
    slow_refusal = gql(
        status=400,
        json={"errors": [{"message": "Unknown directive 'gdosDir0'"}]},
        elapsed=6.0,
    )
    client = FakeClient(_DUPLICATE_DIRECTIVE, slow_refusal, healthy(0.05))
    result = DirectiveOverloadingCheck().run(client, baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE
    assert "before the rejection" in result.summary or "work happens" in result.summary


def test_unknown_directives_refused_quickly_are_protected():
    fast_refusal = gql(
        status=400, json={"errors": [{"message": "Unknown directive 'gdosDir0'"}]}
    )
    client = FakeClient(_DUPLICATE_DIRECTIVE, fast_refusal)
    result = DirectiveOverloadingCheck().run(client, baseline=0.05)
    assert result.verdict is Verdict.PROTECTED


def test_slow_refusal_is_vulnerable_for_any_vector():
    """A limit that costs 100x baseline to enforce is not much of a limit."""
    slow_reject = gql(
        status=400,
        json={"errors": [{"message": "Query depth exceeds maximum"}]},
        elapsed=8.0,
    )
    result = QueryDepthCheck().run(
        FakeClient(slow_reject, healthy(0.05)), baseline=0.05
    )
    assert result.verdict is Verdict.VULNERABLE


# --- introspection -----------------------------------------------------------

def test_introspection_enabled_is_vulnerable():
    resp = gql(json={"data": {"__schema": {"types": [{"name": "Query"}]}}})
    result = IntrospectionEnabledCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE
    assert result.evidence["types_exposed"] == 1


def test_introspection_disabled_is_protected():
    resp = gql(status=400, json={"errors": [{"message": "introspection is disabled"}]})
    result = IntrospectionEnabledCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.PROTECTED


def test_introspection_behind_auth_is_inconclusive():
    resp = gql(status=401, json={"errors": [{"message": "Unauthorized"}]})
    result = IntrospectionEnabledCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.INCONCLUSIVE


# --- batching ----------------------------------------------------------------

def test_batching_executes_all_is_vulnerable():
    count = BatchingCheck()._scaled(low=50, medium=250, high=1000)
    resp = gql(json=[{"data": {"__typename": "Query"}}] * count)
    result = BatchingCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE
    assert result.evidence["operations_executed"] == count


def test_batching_array_of_errors_is_protected():
    """Regression: an array of N errors is a rejection, not N executions."""
    count = BatchingCheck()._scaled(low=50, medium=250, high=1000)
    resp = gql(json=[{"errors": [{"message": "batching is not allowed"}]}] * count)
    result = BatchingCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.PROTECTED
    assert result.evidence["operations_executed"] == 0


def test_batching_capped_is_protected():
    resp = gql(json=[{"data": {"__typename": "Query"}}] * 10)
    result = BatchingCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.PROTECTED
    assert result.evidence["operations_executed"] == 10


def test_batching_rejected_is_protected():
    resp = gql(status=400, json={"errors": [{"message": "batching is not allowed"}]})
    result = BatchingCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.PROTECTED


def test_batching_behind_auth_is_inconclusive():
    resp = gql(status=401, json={"errors": [{"message": "Unauthorized"}]})
    result = BatchingCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.INCONCLUSIVE


# --- circular fragment -------------------------------------------------------

def test_circular_fragment_rejected_is_protected():
    resp = gql(json={"errors": [{"message": "Cannot spread fragment within itself"}]})
    result = CircularFragmentCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.PROTECTED


def test_circular_fragment_executed_is_vulnerable():
    resp = gql(json={"data": {"__typename": "Query"}})
    result = CircularFragmentCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE


def test_circular_fragment_behind_auth_is_inconclusive():
    resp = gql(status=403, json={"errors": [{"message": "Forbidden"}]})
    result = CircularFragmentCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.INCONCLUSIVE


# --- scanner -----------------------------------------------------------------

class ScriptedClient:
    """Answers baseline, control and probe queries independently."""

    url = "http://example.test/graphql"

    def __init__(
        self,
        baseline: GraphQLResponse,
        probe: GraphQLResponse,
        control: GraphQLResponse | None = None,
    ) -> None:
        self._baseline = baseline
        self._probe = probe
        self._control = control if control is not None else baseline

    def query(self, query: str, variables=None) -> GraphQLResponse:
        if "GdosBaseline" in query:
            return self._baseline
        if "GdosControl" in query:
            return self._control
        return self._probe

    def post(self, payload) -> GraphQLResponse:
        return self._probe


def test_failed_baseline_marks_every_check_error():
    client = ScriptedClient(baseline=timed_out(), probe=healthy())
    report = Scanner(client, baseline_samples=2, delay=0).run()
    assert report.baseline_ok is False
    assert report.baseline_samples_ok == 0
    assert len(report.results) == len(ALL_CHECKS)
    assert all(r.verdict is Verdict.ERROR for r in report.results)
    assert report.is_conclusive is False
    assert exit_code(report) == 4


def test_failed_baseline_samples_are_excluded_from_the_median():
    """A timed-out sample must not inflate the slow-probe threshold."""

    class FlakyBaseline:
        url = "http://example.test/graphql"

        def __init__(self) -> None:
            self.calls = 0

        def query(self, query: str, variables=None) -> GraphQLResponse:
            self.calls += 1
            return timed_out() if self.calls == 1 else healthy(0.10)

        def post(self, payload) -> GraphQLResponse:
            return healthy(0.10)

    scanner = Scanner(FlakyBaseline(), baseline_samples=3, delay=0)
    baseline, ok = scanner._measure_baseline()
    assert ok == 2
    assert baseline == pytest.approx(0.10)


def test_scan_aborts_and_marks_the_rest_skipped():
    # The endpoint throttles everything, control queries included: the scan
    # must stop rather than record six more PROTECTED verdicts it did not earn.
    client = ScriptedClient(
        baseline=healthy(), probe=gql(status=429), control=gql(status=429)
    )
    report = Scanner(client, baseline_samples=1, delay=0).run()
    assert report.aborted is True
    assert report.abort_reason
    assert len(report.results) == len(ALL_CHECKS)
    # Everything after the aborting check was skipped, not guessed at.
    assert report.results[-1].verdict is Verdict.INCONCLUSIVE
    assert "Not run" in report.results[-1].summary
    assert report.is_conclusive is False


class PhasedClient:
    """Healthy baseline, one check that passes, then a dead endpoint."""

    url = "http://example.test/graphql"

    def query(self, query: str, variables=None) -> GraphQLResponse:
        if "GdosBaseline" in query:
            return healthy()
        if "GdosIntrospectionProbe" in query:
            return gql(
                status=400,
                json={"errors": [{"message": "introspection is disabled"}]},
            )
        return timed_out()

    def post(self, payload) -> GraphQLResponse:
        return timed_out()


def test_aborted_scan_is_never_conclusive_even_with_a_protected_check():
    """Regression: a partial scan must not produce a clean CI result.

    One PROTECTED verdict before the abort used to satisfy `is_conclusive`,
    so `exit_code` returned 0 and the report read "no DoS exposure detected"
    while most vectors were never probed at all.
    """
    report = Scanner(PhasedClient(), baseline_samples=1, delay=0).run()

    assert report.aborted is True
    assert report.is_vulnerable is False
    assert any(r.verdict is Verdict.PROTECTED for r in report.results)
    assert report.is_conclusive is False
    assert exit_code(report) == 4
    assert "no DoS exposure detected" not in to_text(report, color=False)


def test_abort_after_a_vulnerability_still_exits_one():
    """Guarding the fix: `is_vulnerable` is tested before `is_conclusive`."""

    class VulnerableThenDead:
        url = "http://example.test/graphql"

        def query(self, query: str, variables=None) -> GraphQLResponse:
            if "GdosBaseline" in query:
                return healthy()
            if "GdosIntrospectionProbe" in query:
                return gql(json={"data": {"__schema": {"types": [{"name": "Q"}]}}})
            return timed_out()

        def post(self, payload) -> GraphQLResponse:
            return timed_out()

    report = Scanner(VulnerableThenDead(), baseline_samples=1, delay=0).run()
    assert report.aborted is True
    assert report.is_vulnerable is True
    assert exit_code(report) == 1


def test_clean_scan_is_conclusive():
    client = ScriptedClient(
        baseline=healthy(),
        probe=gql(status=400, json={"errors": [{"message": "query depth exceeds maximum"}]}),
    )
    report = Scanner(client, baseline_samples=1, delay=0).run()
    assert report.is_vulnerable is False
    assert report.is_conclusive is True
    assert exit_code(report) == 0


def test_vulnerable_scan_exits_one():
    client = ScriptedClient(baseline=healthy(), probe=healthy())
    report = Scanner(client, baseline_samples=1, delay=0).run()
    assert report.is_vulnerable is True
    assert exit_code(report) == 1


# --- reporting ---------------------------------------------------------------

def _sample_report() -> ScanReport:
    check = AliasOverloadingCheck()
    count = check._scaled(low=200, medium=1000, high=5000)
    results = [check.run(FakeClient(gql(json=_alias_data(count))), 0.05)]
    return ScanReport(
        url="http://example.test/graphql",
        started_at="2026-06-24T00:00:00+00:00",
        finished_at="2026-06-24T00:00:01+00:00",
        baseline_seconds=0.05,
        results=results,
        baseline_samples_ok=3,
    )


def test_reporting_json_and_text():
    report = _sample_report()
    assert report.is_vulnerable is True

    import json
    parsed = json.loads(to_json(report))
    assert parsed["is_vulnerable"] is True
    assert parsed["is_conclusive"] is True
    assert parsed["baseline_ok"] is True
    assert parsed["aborted"] is False
    assert parsed["results"][0]["verdict"] == "VULNERABLE"

    text = to_text(report, color=False)
    assert "VULNERABLE" in text
    assert "FAIL" in text


def test_inconclusive_report_is_not_rendered_as_clean():
    client = ScriptedClient(baseline=healthy(), probe=gql(status=401))
    report = Scanner(client, baseline_samples=1, delay=0).run()
    text = to_text(report, color=False)
    assert "RESULT: INCONCLUSIVE" in text
    assert "no DoS exposure detected" not in text
