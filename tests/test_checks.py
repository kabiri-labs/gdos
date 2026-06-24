"""Unit tests for the resilience checks and verdict classification.

These tests exercise the decision logic with a fake client, so no network
access (and no live GraphQL server) is required.
"""

from __future__ import annotations

import pytest

from gdos.checks import (
    AliasOverloadingCheck,
    BatchingCheck,
    CircularFragmentCheck,
    IntrospectionEnabledCheck,
    QueryDepthCheck,
)
from gdos.checks.base import Verdict, response_indicates_limit
from gdos.client import GraphQLResponse
from gdos.reporting import to_json, to_text
from gdos.scanner import ScanReport


class FakeClient:
    """A GraphQLClient stand-in that replays a queued response."""

    url = "http://example.test/graphql"

    def __init__(self, response: GraphQLResponse) -> None:
        self._response = response
        self.last_query: str | None = None
        self.last_payload: object = None

    def query(self, query: str, variables=None) -> GraphQLResponse:
        self.last_query = query
        return self._response

    def post(self, payload) -> GraphQLResponse:
        self.last_payload = payload
        return self._response


def gql(json=None, status=200, elapsed=0.05, **kw) -> GraphQLResponse:
    return GraphQLResponse(status_code=status, elapsed=elapsed, json=json, **kw)


# --- response_indicates_limit ------------------------------------------------

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


# --- amplification classification --------------------------------------------

def test_alias_protected_when_rejected():
    resp = gql(status=400, json={"errors": [{"message": "max alias count exceeded"}]})
    result = AliasOverloadingCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.PROTECTED


def test_alias_vulnerable_when_accepted():
    resp = gql(status=200, json={"data": {"a0": "Query"}})
    result = AliasOverloadingCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE
    assert result.evidence["alias_count"] > 0


def test_vulnerable_on_timeout():
    resp = GraphQLResponse(status_code=None, elapsed=15.0, timed_out=True)
    result = QueryDepthCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE


def test_vulnerable_when_slow():
    resp = gql(status=200, json={"data": {"__type": {}}}, elapsed=5.0)
    result = QueryDepthCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE


def test_error_on_transport_failure():
    resp = GraphQLResponse(status_code=None, elapsed=0.1, error="connection refused")
    result = AliasOverloadingCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.ERROR


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


# --- batching ----------------------------------------------------------------

def test_batching_executes_all_is_vulnerable():
    count = BatchingCheck()._scaled(low=50, medium=250, high=1000)
    resp = gql(json=[{"data": {"__typename": "Query"}}] * count)
    result = BatchingCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE


def test_batching_rejected_is_protected():
    resp = gql(status=400, json={"errors": [{"message": "batching is not allowed"}]})
    result = BatchingCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.PROTECTED


# --- circular fragment -------------------------------------------------------

def test_circular_fragment_rejected_is_protected():
    resp = gql(json={"errors": [{"message": "Cannot spread fragment within itself"}]})
    result = CircularFragmentCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.PROTECTED


def test_circular_fragment_executed_is_vulnerable():
    resp = gql(json={"data": {"__typename": "Query"}})
    result = CircularFragmentCheck().run(FakeClient(resp), baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE


# --- reporting ---------------------------------------------------------------

def _sample_report() -> ScanReport:
    resp = gql(json={"data": {"a0": "Query"}})
    results = [AliasOverloadingCheck().run(FakeClient(resp), 0.05)]
    return ScanReport(
        url="http://example.test/graphql",
        started_at="2026-06-24T00:00:00+00:00",
        finished_at="2026-06-24T00:00:01+00:00",
        baseline_seconds=0.05,
        results=results,
    )


def test_reporting_json_and_text():
    report = _sample_report()
    assert report.is_vulnerable is True

    import json
    parsed = json.loads(to_json(report))
    assert parsed["is_vulnerable"] is True
    assert parsed["results"][0]["verdict"] == "VULNERABLE"

    text = to_text(report, color=False)
    assert "VULNERABLE" in text
    assert "FAIL" in text
