"""Unit tests for the persisted-query and transport/surface checks.

Driven by a stub client, so no network access is required.
"""

from __future__ import annotations

import pytest

from gdos.checks import (
    FieldSuggestionCheck,
    GetMethodCheck,
    IncrementalDeliveryCheck,
    PersistedQueryCheck,
)
from gdos.checks.base import Verdict
from gdos.client import GraphQLResponse


class StubClient:
    """Replays queued responses and records how each request was sent.

    Which transport a check used is part of what these tests assert, so every
    call is recorded with its method rather than only its payload.
    """

    url = "http://example.test/graphql"

    def __init__(self, *responses: GraphQLResponse) -> None:
        self._responses = list(responses) or [gql()]
        self.calls: list[tuple[str, object]] = []

    def _next(self) -> GraphQLResponse:
        if len(self._responses) > 1:
            return self._responses.pop(0)
        return self._responses[0]

    def query(self, query: str, variables=None) -> GraphQLResponse:
        self.calls.append(("POST", query))
        return self._next()

    def post(self, payload) -> GraphQLResponse:
        self.calls.append(("POST", payload))
        return self._next()

    def get(self, query: str, variables=None) -> GraphQLResponse:
        self.calls.append(("GET", query))
        return self._next()

    @property
    def methods(self) -> list[str]:
        return [m for m, _ in self.calls]


def gql(json=None, status=200, elapsed=0.05, **kw) -> GraphQLResponse:
    return GraphQLResponse(status_code=status, elapsed=elapsed, json=json, **kw)


def errors(*messages: str, status: int = 200, code: str | None = None):
    payload = [
        {"message": m, **({"extensions": {"code": code}} if code else {})}
        for m in messages
    ]
    return gql(status=status, json={"errors": payload, "data": None})


def healthy() -> GraphQLResponse:
    return gql(json={"data": {"__typename": "Query"}})


# --- persisted queries -------------------------------------------------------

APQ_MISS = errors("PersistedQueryNotFound", code="PERSISTED_QUERY_NOT_FOUND")
APQ_UNSUPPORTED = errors(
    "PersistedQueryNotSupported", code="PERSISTED_QUERY_NOT_SUPPORTED"
)


def test_apq_unsupported_is_protected():
    result = PersistedQueryCheck().run(StubClient(APQ_UNSUPPORTED), baseline=0.05)
    assert result.verdict is Verdict.PROTECTED
    assert result.evidence["apq"] == "not-supported"


def test_apq_absent_is_protected():
    """A server that just wants a query string has no APQ cache to fill."""
    resp = errors("GraphQL queries must include a `query` string", status=400)
    result = PersistedQueryCheck().run(StubClient(resp), baseline=0.05)
    assert result.verdict is Verdict.PROTECTED
    assert result.evidence["apq"] == "absent"


def test_apq_enabled_without_optin_never_writes():
    """The gate is the point: no opt-in, no registration request.

    Detecting APQ is read-only. Measuring whether its cache is bounded means
    writing to someone else's server, so the check must stop at the detection
    and say so.
    """
    client = StubClient(APQ_MISS)
    result = PersistedQueryCheck(allow_state_changing=False).run(client, baseline=0.05)

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.evidence["apq"] == "enabled"
    assert result.evidence["registration_attempted"] is False
    assert len(client.calls) == 1, "a second request would be a write to the target"
    assert "--apq-register" in result.summary


def test_apq_default_is_deny():
    """The gate defaults shut even when nobody passes the argument."""
    client = StubClient(APQ_MISS)
    PersistedQueryCheck().run(client, baseline=0.05)
    assert len(client.calls) == 1


def test_apq_hash_verified_is_protected():
    client = StubClient(
        APQ_MISS, errors("provided sha does not match query", status=400)
    )
    result = PersistedQueryCheck(allow_state_changing=True).run(client, baseline=0.05)
    assert result.verdict is Verdict.PROTECTED
    assert result.evidence["registration_attempted"] is True
    assert len(client.calls) == 2


def test_apq_unverified_hash_is_vulnerable():
    """Accepting a document under someone else's hash hands over the cache key."""
    client = StubClient(APQ_MISS, healthy())
    result = PersistedQueryCheck(allow_state_changing=True).run(client, baseline=0.05)

    assert result.verdict is Verdict.VULNERABLE
    assert result.evidence["registration_attempted"] is True
    # The report must say exactly what was written to the target.
    assert "submitted_hash" in result.evidence
    assert "submitted_query" in result.evidence
    assert "One entry was registered" in result.summary


def test_apq_behind_auth_is_inconclusive():
    resp = errors("Unauthorized", status=401)
    result = PersistedQueryCheck().run(StubClient(resp), baseline=0.05)
    assert result.verdict is Verdict.INCONCLUSIVE


# --- field suggestions -------------------------------------------------------

def test_field_suggestion_leak_is_vulnerable():
    resp = errors(
        "Cannot query field '__typenam' on type 'Query'. Did you mean '__typename'?"
    )
    result = FieldSuggestionCheck().run(StubClient(resp), baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE
    assert result.evidence["suggestions"] is True


def test_validation_error_without_a_suggestion_is_protected():
    """Negative: rejecting an unknown field is correct, not a leak."""
    resp = errors("Cannot query field '__typenam' on type 'Query'.")
    result = FieldSuggestionCheck().run(StubClient(resp), baseline=0.05)
    assert result.verdict is Verdict.PROTECTED
    assert result.evidence["suggestions"] is False


def test_masked_errors_are_protected():
    resp = errors("Unexpected error.", status=500)
    result = FieldSuggestionCheck().run(StubClient(resp), baseline=0.05)
    assert result.verdict is Verdict.PROTECTED


def test_field_suggestion_behind_auth_is_inconclusive():
    resp = errors("You are not authorized to access this resource")
    result = FieldSuggestionCheck().run(StubClient(resp), baseline=0.05)
    assert result.verdict is Verdict.INCONCLUSIVE


# --- GET transport -----------------------------------------------------------

def test_get_rejected_is_protected():
    client = StubClient(gql(status=405))
    result = GetMethodCheck().run(client, baseline=0.05)
    assert result.verdict is Verdict.PROTECTED
    assert client.methods == ["GET"], "the check must probe the GET transport"


def test_get_executed_is_vulnerable():
    count = GetMethodCheck()._ALIAS_COUNT
    resp = gql(json={"data": {f"g{i}": "Query" for i in range(count)}})
    result = GetMethodCheck().run(StubClient(resp), baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE
    assert result.evidence["aliases_resolved"] == count


def test_get_covered_by_limits_is_protected():
    resp = errors("Too many aliases: maximum of 15 allowed", status=400)
    result = GetMethodCheck().run(StubClient(resp), baseline=0.05)
    assert result.verdict is Verdict.PROTECTED


def test_get_url_too_long_is_protected():
    result = GetMethodCheck().run(StubClient(gql(status=414)), baseline=0.05)
    assert result.verdict is Verdict.PROTECTED


def test_get_probe_stays_small():
    """A big URL would test length limits instead of the policy question."""
    client = StubClient(gql(status=405))
    GetMethodCheck().run(client, baseline=0.05)
    _, sent = client.calls[0]
    assert len(sent) < 4096, "the GET probe must stay well inside URL limits"


# --- incremental delivery ----------------------------------------------------

def test_defer_unsupported_is_protected():
    """Negative: a server without @defer must fail the document in validation."""
    resp = errors("Unknown directive '@defer'.", status=400)
    result = IncrementalDeliveryCheck().run(StubClient(resp), baseline=0.05)
    assert result.verdict is Verdict.PROTECTED
    assert result.evidence["defer_count"] > 0


def test_defer_stream_accepted_is_vulnerable():
    resp = GraphQLResponse(
        status_code=200,
        elapsed=0.2,
        content_type="multipart/mixed; boundary=-",
        text="--\r\ncontent-type: application/json\r\n\r\n{}",
        json=None,
    )
    result = IncrementalDeliveryCheck().run(StubClient(resp), baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE
    assert result.evidence["content_type"].startswith("multipart/")


def test_defer_executed_as_plain_json_is_vulnerable():
    """Some servers collapse deferred payloads into one document and still ran."""
    resp = gql(json={"data": {"__type": {"name": "String"}}})
    result = IncrementalDeliveryCheck().run(StubClient(resp), baseline=0.05)
    assert result.verdict is Verdict.VULNERABLE


def test_defer_labels_are_unique():
    """Repeated labels would be refused as invalid, not as excessive."""
    check = IncrementalDeliveryCheck()
    document = check._build(25)
    labels = [p.split('"')[1] for p in document.split("@defer(label: ")[1:]]
    assert len(labels) == 25
    assert len(set(labels)) == 25


@pytest.mark.parametrize("intensity", ["low", "medium", "high"])
def test_defer_count_scales_with_intensity(intensity):
    check = IncrementalDeliveryCheck(intensity=intensity)
    client = StubClient(errors("Unknown directive '@defer'.", status=400))
    result = check.run(client, baseline=0.05)
    assert result.evidence["defer_count"] == check._scaled(50, 250, 1000)
