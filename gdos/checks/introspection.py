"""Introspection-related checks."""

from __future__ import annotations

from gdos.checks.base import (
    Check,
    CheckResult,
    Severity,
    Verdict,
    response_indicates_limit,
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
        schema = None
        if isinstance(resp.json, dict):
            schema = (resp.json.get("data") or {}).get("__schema")
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
        if response_indicates_limit(resp) or resp.graphql_errors:
            return self._result(
                Verdict.PROTECTED,
                "Introspection appears to be disabled or restricted.",
                resp,
                baseline,
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
    amplification primitive.
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
        result = self._classify_amplification(resp, baseline, "deep introspection")
        result.evidence["nesting_depth"] = depth
        return result
