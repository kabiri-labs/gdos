"""Introspection-related checks."""

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

_MINIMAL_INTROSPECTION = """
query GdosIntrospectionProbe {
  __schema {
    queryType { name }
    types { name kind }
  }
}
"""


class IntrospectionEnabledCheck(Check):
    """Detects whether schema introspection is exposed.

    Introspection is rarely needed by production clients and dramatically
    enlarges the attack surface (it lets an attacker discover expensive fields
    and craft targeted complexity attacks). Disabling it in production is a
    widely recommended hardening step.
    """

    name = "introspection-enabled"
    vector = "Schema introspection exposure"
    severity = Severity.MEDIUM
    remediation = (
        "Disable introspection in production (e.g. GraphQL-JS "
        "`NoSchemaIntrospectionCustomRule`, Apollo `introspection: false`, "
        "or your framework's equivalent). Keep it enabled only in non-prod."
    )

    def run(self, client: GraphQLClient, baseline: float) -> CheckResult:
        resp = client.query(_MINIMAL_INTROSPECTION)

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
                    "The introspection probe timed out while trivial queries "
                    "still succeed. Introspection state is unknown, but a schema "
                    "that cannot be listed inside the timeout is itself an "
                    "expensive operation to expose.",
                    resp,
                    baseline,
                    evidence={"control_probe": "healthy"},
                    severity=Severity.LOW,
                )
            return self._unreachable(resp, baseline, "The introspection probe timed out")

        if resp.truncated:
            return self._result(
                Verdict.VULNERABLE,
                "Introspection is ENABLED and the schema is large enough that "
                f"the response hit the {resp.bytes_read} byte read cap — the "
                "full type and field catalogue is readable by anyone, and "
                "serving it is itself expensive.",
                resp,
                baseline,
                evidence={"response_truncated": True, "bytes_read": resp.bytes_read},
            )

        schema = (resp.data or {}).get("__schema")
        if schema:
            type_count = len(schema.get("types") or [])
            return self._result(
                Verdict.VULNERABLE,
                "Introspection is ENABLED — the full schema is readable by anyone, "
                "exposing every type and field for reconnaissance and targeted "
                "complexity attacks.",
                resp,
                baseline,
                evidence={"types_exposed": type_count},
            )

        rejection = classify_rejection(resp)
        if rejection is Rejection.AUTH:
            return self._auth_wall(resp, baseline, "introspection")
        if rejection is Rejection.RATE:
            control = self._control(client)
            return self._result(
                Verdict.INCONCLUSIVE,
                "Endpoint throttled the introspection probe, so its introspection "
                "state could not be determined.",
                resp,
                baseline,
                evidence={"rejection": rejection.value},
                severity=Severity.LOW,
                abort_scan=not endpoint_healthy(control),
            )
        if rejection in (Rejection.LIMIT, Rejection.SIZE, Rejection.VALIDATION):
            return self._result(
                Verdict.PROTECTED,
                "Introspection appears to be disabled or restricted.",
                resp,
                baseline,
                evidence={"rejection": rejection.value},
                severity=Severity.INFO,
            )
        return self._result(
            Verdict.INCONCLUSIVE,
            "Could not confirm introspection state (unexpected response shape).",
            resp,
            baseline,
            severity=Severity.LOW,
        )


class DeepIntrospectionCheck(Check):
    """Recursive introspection that nests ``fields -> type -> fields`` deeply.

    Even when introspection is enabled, a server should bound query depth /
    complexity so a recursive introspection query cannot be used as an
    amplification primitive (CVE-2024-40094).
    """

    name = "deep-introspection"
    vector = "Recursive introspection amplification"
    severity = Severity.HIGH
    remediation = (
        "Enforce a maximum query depth and/or complexity budget that also "
        "applies to introspection fields, and disable introspection in prod."
    )

    def _build(self, depth: int) -> str:
        fragment = "name"
        for _ in range(depth):
            fragment = (
                "name kind ofType { %s } fields { name type { %s } }"
                % (fragment, fragment)
            )
        return "query GdosDeepIntrospection { __schema { types { %s } } }" % fragment

    def run(self, client: GraphQLClient, baseline: float) -> CheckResult:
        depth = self._scaled(low=4, medium=8, high=12)
        resp = client.query(self._build(depth))
        result = self._classify_amplification(
            client, resp, baseline, "deep introspection"
        )
        result.evidence["nesting_depth"] = depth
        return result
