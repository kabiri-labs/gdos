"""Array-batching and circular-fragment checks."""

from __future__ import annotations

from gdos.checks.base import (
    Check,
    CheckResult,
    Severity,
    Verdict,
    response_indicates_limit,
)
from gdos.client import GraphQLClient


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

        if resp.error and not resp.timed_out:
            return self._result(
                Verdict.ERROR, f"Probe could not be delivered: {resp.error}",
                resp, baseline, severity=Severity.INFO,
            )
        if resp.timed_out:
            return self._result(
                Verdict.VULNERABLE,
                "Server did not respond within the timeout for a batch of "
                f"{count} operations — likely no batch limit.",
                resp, baseline, evidence={"batch_size": count},
            )
        # A server that accepts batching answers with a JSON array of results.
        if isinstance(resp.json, list):
            if len(resp.json) >= count:
                verdict, summary, sev = (
                    Verdict.VULNERABLE,
                    f"Server executed all {count} batched operations — array "
                    "batching is enabled with no effective size cap.",
                    self.severity,
                )
            else:
                verdict, summary, sev = (
                    Verdict.PROTECTED,
                    f"Server returned only {len(resp.json)} of {count} batched "
                    "operations — a batch limit appears to be enforced.",
                    Severity.INFO,
                )
            return self._result(
                verdict, summary, resp, baseline,
                evidence={"batch_size": count, "results_returned": len(resp.json)},
                severity=sev,
            )
        if response_indicates_limit(resp) or (resp.graphql_errors and not resp.has_data):
            return self._result(
                Verdict.PROTECTED,
                "Server rejected array batching (batching disabled or limited).",
                resp, baseline, evidence={"batch_size": count}, severity=Severity.INFO,
            )
        return self._result(
            Verdict.INCONCLUSIVE,
            f"Unexpected response to batch probe (status {resp.status_code}).",
            resp, baseline, evidence={"batch_size": count}, severity=Severity.LOW,
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
                Verdict.ERROR, f"Probe could not be delivered: {resp.error}",
                resp, baseline, severity=Severity.INFO,
            )
        if resp.timed_out:
            return self._result(
                Verdict.VULNERABLE,
                "Server hung on a circular fragment — validation does not reject "
                "fragment cycles (unbounded recursion risk).",
                resp, baseline,
            )
        # Correct behaviour: rejected during validation, no data returned.
        if resp.graphql_errors and not resp.has_data:
            return self._result(
                Verdict.PROTECTED,
                "Server correctly rejected the circular fragment during validation.",
                resp, baseline, severity=Severity.INFO,
            )
        if resp.has_data:
            return self._result(
                Verdict.VULNERABLE,
                "Server executed a document containing a fragment cycle — its "
                "validation phase does not enforce the no-cycles rule.",
                resp, baseline,
            )
        return self._result(
            Verdict.INCONCLUSIVE,
            f"Unexpected response to circular-fragment probe (status {resp.status_code}).",
            resp, baseline, severity=Severity.LOW,
        )
