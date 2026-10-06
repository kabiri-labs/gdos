"""Automatic Persisted Queries (APQ).

APQ lets a client send a SHA-256 hash instead of a query string: the server
looks the hash up in a cache and, on a miss, asks for the full document and
stores it. Apollo Server 3 shipped this on by default with an *unbounded*
cache, so an attacker could register arbitrarily many distinct documents and
exhaust the server's memory. The documented fixes are a bounded cache or
turning the feature off.

A single bounded probe cannot measure whether a cache is bounded — that would
take many registrations, which is flooding. What it can establish is whether
APQ is reachable at all, and, when the operator opts in, whether the server
verifies that the hash actually matches the document it is given. A server that
does not verify accepts attacker-chosen hash/document pairs, which makes both
cache poisoning and unbounded growth trivial.
"""

from __future__ import annotations

import hashlib

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

_PROBE_QUERY = "query GdosApqProbe { __typename }"

# A hash that no real document will have, used to provoke the cache-miss
# response that reveals whether APQ is wired up at all.
_ABSENT_HASH = hashlib.sha256(b"gdos-apq-presence-probe").hexdigest()

# Deliberately not the hash of _PROBE_QUERY. A server that verifies the pair
# must refuse this; one that stores it is taking the client's word for it.
_MISMATCHED_HASH = hashlib.sha256(b"gdos-apq-mismatch-probe").hexdigest()


def _apq_payload(sha256_hash: str, query: str | None = None) -> dict:
    payload: dict = {
        "extensions": {
            "persistedQuery": {"version": 1, "sha256Hash": sha256_hash}
        }
    }
    if query is not None:
        payload["query"] = query
    return payload


def _mentions(resp, *needles: str) -> bool:
    haystack = resp.error_messages()
    codes = " ".join(
        str((e.get("extensions") or {}).get("code", "")) for e in resp.graphql_errors
    ).lower()
    return any(n in haystack or n in codes for n in needles)


class PersistedQueryCheck(Check):
    """Whether APQ is reachable, and whether it verifies hash/document pairs."""

    name = "persisted-queries"
    vector = "Automatic Persisted Queries cache"
    severity = Severity.HIGH
    remediation = (
        "Bound the persisted-query cache (Apollo Server: `cache: 'bounded'`) or "
        "disable automatic persisted queries entirely "
        "(`persistedQueries: false`), and prefer a build-time allowlist of "
        "known documents over letting clients register new ones at runtime."
    )

    def run(self, client: GraphQLClient, baseline: float) -> CheckResult:
        resp = client.post(_apq_payload(_ABSENT_HASH))

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
                    "The APQ presence probe timed out while trivial queries "
                    "still succeed; APQ state could not be determined.",
                    resp,
                    baseline,
                    severity=Severity.LOW,
                )
            return self._unreachable(resp, baseline, "The APQ probe timed out")

        rejection = classify_rejection(resp)
        if rejection is Rejection.AUTH:
            return self._auth_wall(resp, baseline, "APQ")
        if rejection is Rejection.RATE:
            return self._throttled(client, resp, baseline, "APQ")

        # A server error says nothing about whether APQ exists, and may mean
        # the probe broke the APQ path. Either way it is not protection.
        if resp.status_code is not None and resp.status_code >= 500:
            if endpoint_healthy(self._control(client)):
                return self._result(
                    Verdict.INCONCLUSIVE,
                    f"Endpoint returned {resp.status_code} to an APQ request "
                    "while still serving trivial queries. The APQ path errored "
                    "rather than answering, so whether persisted queries are "
                    "enabled could not be determined — a server error on a "
                    "well-formed APQ request is worth investigating on its own.",
                    resp,
                    baseline,
                    evidence={"apq": "errored", "control_probe": "healthy"},
                    severity=Severity.MEDIUM,
                )
            return self._unreachable(
                resp, baseline, f"The APQ probe returned {resp.status_code}"
            )

        # Explicitly off, or not implemented: both are the hardened answer.
        if _mentions(resp, "persistedquerynotsupported", "persisted_query_not_supported"):
            return self._result(
                Verdict.PROTECTED,
                "Server reports persisted queries as unsupported — the cache "
                "cannot be filled by clients.",
                resp,
                baseline,
                evidence={"apq": "not-supported"},
                severity=Severity.INFO,
            )
        if not _mentions(resp, "persistedquerynotfound", "persisted_query_not_found"):
            # Only a clear, served answer supports concluding APQ is absent.
            if resp.status_code is None or not 200 <= resp.status_code < 500:
                return self._result(
                    Verdict.INCONCLUSIVE,
                    f"Unexpected answer to an APQ request (status "
                    f"{resp.status_code}); whether persisted queries are "
                    "enabled could not be determined.",
                    resp,
                    baseline,
                    evidence={"apq": "unknown"},
                    severity=Severity.LOW,
                )
            return self._result(
                Verdict.PROTECTED,
                "Endpoint did not answer an APQ request with a cache-miss, so "
                "automatic persisted queries do not appear to be wired up.",
                resp,
                baseline,
                evidence={"apq": "absent"},
                severity=Severity.INFO,
            )

        # APQ is reachable. Whether its cache is bounded cannot be read from a
        # single request, and filling it would be flooding.
        if not self.allow_state_changing:
            return self._result(
                Verdict.INCONCLUSIVE,
                "Automatic persisted queries are ENABLED: the endpoint answered "
                "an unknown hash with a cache miss, so clients can register new "
                "documents at runtime. Whether that cache is bounded cannot be "
                "determined without writing to it, which GDoS will not do "
                "unless asked. Re-run with --apq-register to test whether the "
                "server verifies hash/document pairs, or confirm the cache "
                "bound in your server configuration.",
                resp,
                baseline,
                evidence={"apq": "enabled", "registration_attempted": False},
                severity=Severity.LOW,
            )

        return self._probe_hash_verification(client, baseline)

    def _probe_hash_verification(
        self, client: GraphQLClient, baseline: float
    ) -> CheckResult:
        """Offer a document under a hash that is not its own.

        This writes at most one entry to the target's cache, which is why it is
        gated behind an explicit opt-in.
        """
        resp = client.post(_apq_payload(_MISMATCHED_HASH, _PROBE_QUERY))
        evidence: dict[str, object] = {
            "apq": "enabled",
            "registration_attempted": True,
            "submitted_hash": _MISMATCHED_HASH,
            "submitted_query": _PROBE_QUERY,
        }

        if resp.error and not resp.timed_out:
            return self._result(
                Verdict.ERROR,
                f"Registration probe could not be delivered: {resp.error}",
                resp,
                baseline,
                evidence=evidence,
                severity=Severity.INFO,
            )
        if resp.timed_out:
            return self._result(
                Verdict.INCONCLUSIVE,
                "The APQ registration probe timed out; hash verification could "
                "not be determined.",
                resp,
                baseline,
                evidence=evidence,
                severity=Severity.LOW,
            )

        rejection = classify_rejection(resp)
        if rejection is Rejection.AUTH:
            return self._auth_wall(resp, baseline, "APQ registration")
        if rejection is Rejection.RATE:
            return self._throttled(client, resp, baseline, "APQ registration")
        if resp.status_code is not None and resp.status_code >= 500:
            return self._result(
                Verdict.INCONCLUSIVE,
                f"Endpoint returned {resp.status_code} to the registration "
                "probe, so whether it verifies hash/document pairs could not "
                "be determined.",
                resp,
                baseline,
                evidence=evidence,
                severity=Severity.LOW,
            )

        if _mentions(
            resp,
            "does not match",
            "provided sha",
            "hash mismatch",
            "persisted_query_hash_mismatch",
            "invalid hash",
        ):
            return self._result(
                Verdict.PROTECTED,
                "Server rejected a document offered under a hash that was not "
                "its own — hash/document pairs are verified, so clients cannot "
                "choose their own cache keys.",
                resp,
                baseline,
                evidence=evidence,
                severity=Severity.INFO,
            )

        if resp.has_data:
            return self._result(
                Verdict.VULNERABLE,
                "Server accepted and executed a document submitted under a "
                f"hash that is not its SHA-256 ({_MISMATCHED_HASH[:12]}…). It "
                "does not verify hash/document pairs, so an attacker chooses "
                "both the cache key and its contents: the cache can be filled "
                "with arbitrary entries until memory is exhausted, and a hash a "
                "legitimate client will later request can be poisoned. One "
                "entry was registered by this probe.",
                resp,
                baseline,
                evidence=evidence,
            )

        return self._result(
            Verdict.INCONCLUSIVE,
            "Server neither executed the mismatched document nor named a hash "
            f"mismatch (status {resp.status_code}); manual review recommended.",
            resp,
            baseline,
            evidence=evidence,
            severity=Severity.LOW,
        )
