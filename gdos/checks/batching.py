"""Array-batching and circular-fragment checks."""

from __future__ import annotations

from typing import Any

from gdos.checks.base import (
    Check,
    CheckResult,
    Rejection,
    Severity,
    Verdict,
    classify_rejection,
    endpoint_healthy,
)
from gdos.client import GraphQLClient, GraphQLResponse


def _executed_entries(entries: list[Any]) -> int:
    """How many batch entries actually carry executed results."""
    return sum(
        1
        for e in entries
        if isinstance(e, dict) and e.get("data") not in (None, {})
    )


def _first_error_entry(entries: list[Any]) -> dict[str, Any] | None:
    for e in entries:
        if isinstance(e, dict) and e.get("errors"):
            return e
    return None


class BatchingCheck(Check):
    """Array batching: a JSON array of many operations in one HTTP request.

    Array batching multiplies server work per connection and bypasses naive
    per-request rate limits. Many servers should cap (or disable) batch size.
    """

    name = "array-batching"
    vector = "Array request batching"
    severity = Severity.HIGH
    remediation = (
        "Cap the maximum batch size (or disable array batching), and apply rate "
        "limits / complexity budgets across the whole batch rather than per item."
    )

    def run(self, client: GraphQLClient, baseline: float) -> CheckResult:
        count = self._scaled(low=50, medium=250, high=1000)
        batch = [{"query": "query GdosBatch%d { __typename }" % i} for i in range(count)]
        resp = client.post(batch)
        evidence: dict[str, object] = {"batch_size": count}

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
                evidence["control_probe"] = "healthy"
                return self._result(
                    Verdict.VULNERABLE,
                    f"Server did not respond within the timeout for a batch of "
                    f"{count} operations, yet still answers a trivial query — "
                    "the batch exhausted it and no batch limit rejected it.",
                    resp,
                    baseline,
                    evidence=evidence,
                )
            return self._unreachable(
                resp, baseline, f"The batch of {count} operations timed out"
            )
        if resp.status_code is not None and resp.status_code >= 500:
            if endpoint_healthy(self._control(client)):
                evidence["control_probe"] = "healthy"
                return self._result(
                    Verdict.VULNERABLE,
                    f"Server returned {resp.status_code} on a batch of {count} "
                    "operations while still serving trivial queries — the batch "
                    "reached execution and erred the server.",
                    resp,
                    baseline,
                    evidence=evidence,
                )
            return self._unreachable(
                resp, baseline, f"The batch probe returned {resp.status_code}"
            )

        if resp.truncated:
            evidence["response_truncated"] = True
            evidence["bytes_read"] = resp.bytes_read
            return self._result(
                Verdict.VULNERABLE,
                f"A batch of {count} operations produced at least "
                f"{resp.bytes_read} bytes and was still arriving when the read "
                "cap stopped it — the batch was executed at scale.",
                resp,
                baseline,
                evidence=evidence,
            )

        # A server that accepts batching answers with a JSON array of results.
        # An array of *errors* is a rejection, not an execution, so count only
        # the entries that actually carry data.
        if isinstance(resp.json, list):
            returned = len(resp.json)
            executed = _executed_entries(resp.json)
            evidence["results_returned"] = returned
            evidence["operations_executed"] = executed

            if executed >= count:
                return self._result(
                    Verdict.VULNERABLE,
                    f"Server executed all {count} batched operations — array "
                    "batching is enabled with no effective size cap.",
                    resp,
                    baseline,
                    evidence=evidence,
                )
            if executed > 0:
                return self._result(
                    Verdict.PROTECTED,
                    f"Server executed only {executed} of {count} batched "
                    "operations — a batch limit appears to be enforced.",
                    resp,
                    baseline,
                    evidence=evidence,
                    severity=Severity.INFO,
                )

            entry = _first_error_entry(resp.json)
            rejection = (
                classify_rejection(
                    GraphQLResponse(
                        status_code=resp.status_code, elapsed=resp.elapsed, json=entry
                    )
                )
                if entry is not None
                else Rejection.NONE
            )
            evidence["rejection"] = rejection.value
            if rejection is Rejection.AUTH:
                return self._auth_wall(resp, baseline, "array batching")
            if rejection is Rejection.RATE:
                return self._throttled(client, resp, baseline, "array batching")
            if entry is not None:
                return self._result(
                    Verdict.PROTECTED,
                    f"Server returned {returned} batch entries but executed none "
                    "of them — array batching is rejected or limited.",
                    resp,
                    baseline,
                    evidence=evidence,
                    severity=Severity.INFO,
                )
            return self._result(
                Verdict.INCONCLUSIVE,
                f"Server returned {returned} batch entries with neither data nor "
                "errors; manual review recommended.",
                resp,
                baseline,
                evidence=evidence,
                severity=Severity.LOW,
            )

        rejection = classify_rejection(resp)
        evidence["rejection"] = rejection.value
        if rejection is Rejection.AUTH:
            return self._auth_wall(resp, baseline, "array batching")
        if rejection is Rejection.RATE:
            return self._throttled(client, resp, baseline, "array batching")
        if rejection in (Rejection.LIMIT, Rejection.SIZE, Rejection.VALIDATION):
            return self._result(
                Verdict.PROTECTED,
                "Server rejected array batching (batching disabled or limited).",
                resp,
                baseline,
                evidence=evidence,
                severity=Severity.INFO,
            )
        return self._result(
            Verdict.INCONCLUSIVE,
            f"Unexpected response to batch probe (status {resp.status_code}).",
            resp,
            baseline,
            evidence=evidence,
            severity=Severity.LOW,
        )


class CircularFragmentCheck(Check):
    """A self-referential fragment spread.

    The GraphQL spec forbids fragment cycles and a compliant server MUST reject
    the document during validation. A server that does not reject it can be
    driven into unbounded recursion.
    """

    name = "circular-fragment"
    vector = "Circular fragment spread"
    severity = Severity.HIGH
    remediation = (
        "Use a spec-compliant validation phase that rejects fragment cycles "
        "(rule: 'Fragment spreads must not form cycles'). Keep validation enabled."
    )

    _QUERY = """
    query GdosCircularFragment { __typename ...A }
    fragment A on Query { __typename ...B }
    fragment B on Query { __typename ...A }
    """

    def run(self, client: GraphQLClient, baseline: float) -> CheckResult:
        resp = client.query(self._QUERY)
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
                    "Server hung on a circular fragment while still answering "
                    "trivial queries — validation does not reject fragment "
                    "cycles (unbounded recursion risk).",
                    resp,
                    baseline,
                    evidence={"control_probe": "healthy"},
                )
            return self._unreachable(
                resp, baseline, "The circular-fragment probe timed out"
            )
        if resp.status_code is not None and resp.status_code >= 500:
            if endpoint_healthy(self._control(client)):
                return self._result(
                    Verdict.VULNERABLE,
                    f"Server returned {resp.status_code} on a circular fragment "
                    "while still serving trivial queries — the cycle reached "
                    "execution and blew up (unbounded recursion).",
                    resp,
                    baseline,
                    evidence={"control_probe": "healthy"},
                )
            return self._unreachable(
                resp, baseline, f"The circular-fragment probe returned {resp.status_code}"
            )

        if resp.truncated:
            return self._result(
                Verdict.VULNERABLE,
                "A document containing a fragment cycle produced at least "
                f"{resp.bytes_read} bytes and was still arriving when the read "
                "cap stopped it — the cycle was executed and the output is "
                "unbounded.",
                resp,
                baseline,
                evidence={"response_truncated": True, "bytes_read": resp.bytes_read},
            )

        rejection = classify_rejection(resp)
        if rejection is Rejection.AUTH:
            return self._auth_wall(resp, baseline, "circular fragment")
        if rejection is Rejection.RATE:
            return self._throttled(client, resp, baseline, "circular fragment")

        # A document containing a fragment cycle that produced data was executed
        # despite a mandatory spec rule that should have refused it.
        if resp.has_data:
            return self._result(
                Verdict.VULNERABLE,
                "Server executed a document containing a fragment cycle — its "
                "validation phase does not enforce the no-cycles rule.",
                resp,
                baseline,
            )
        # Correct behaviour: rejected during validation, no data returned.
        if resp.graphql_errors:
            return self._result(
                Verdict.PROTECTED,
                "Server correctly rejected the circular fragment during validation.",
                resp,
                baseline,
                evidence={"rejection": rejection.value},
                severity=Severity.INFO,
            )
        return self._result(
            Verdict.INCONCLUSIVE,
            f"Unexpected response to circular-fragment probe (status {resp.status_code}).",
            resp,
            baseline,
            severity=Severity.LOW,
        )
