"""Universal amplification checks.

These probes rely only on the GraphQL *meta* fields (``__typename``, ``__type``)
that every spec-compliant server exposes, so they work against any endpoint
without prior knowledge of the schema and without needing introspection of the
business types to be enabled.
"""

from __future__ import annotations

from gdos.checks.base import (
    Check,
    CheckResult,
    Severity,
    Verdict,
    rejected_as_duplicate_directive,
)
from gdos.client import GraphQLClient


class AliasOverloadingCheck(Check):
    """Many aliases of the same field in one document (node/alias amplification).

    Aliasing lets a client request the same expensive field hundreds of times in
    a single small request. Without an alias/node limit this is a classic
    amplification vector.
    """

    name = "alias-overloading"
    vector = "Alias-based amplification"
    severity = Severity.HIGH
    remediation = (
        "Enforce an alias count limit and a query complexity/node budget "
        "(e.g. graphql-query-complexity, Apollo `@cost`, envelop max-aliases)."
    )

    def run(self, client: GraphQLClient, baseline: float) -> CheckResult:
        count = self._scaled(low=200, medium=1000, high=5000)
        aliases = " ".join(f"a{i}: __typename" for i in range(count))
        resp = client.query("query GdosAliasProbe { %s }" % aliases)
        result = self._classify_amplification(
            client, resp, baseline, "alias overloading"
        )
        result.evidence["alias_count"] = count

        # Direct evidence of amplification: how many of the requested aliases
        # the server actually resolved. A server that answered with fewer than
        # it was asked for is truncating, which is not the same as executing.
        data = resp.data
        if data is not None:
            resolved = len(data)
            result.evidence["aliases_resolved"] = resolved
            if result.verdict is Verdict.VULNERABLE and resolved < count:
                result.verdict = Verdict.INCONCLUSIVE
                result.severity = Severity.LOW
                result.summary = (
                    f"Server resolved only {resolved} of {count} requested "
                    "aliases — it appears to cap or truncate rather than reject. "
                    "Manual review recommended."
                )
        return result


class FieldDuplicationCheck(Check):
    """The same field repeated many times (duplication amplification).

    Some servers de-duplicate identical fields, but those that don't will do the
    work N times. A node/complexity limit should still count duplicates.
    """

    name = "field-duplication"
    vector = "Field duplication amplification"
    severity = Severity.MEDIUM
    remediation = (
        "Apply a query complexity/node-count limit that accounts for repeated "
        "fields, not just distinct ones."
    )

    def run(self, client: GraphQLClient, baseline: float) -> CheckResult:
        count = self._scaled(low=500, medium=2000, high=10000)
        body = " ".join("__typename" for _ in range(count))
        resp = client.query("query GdosDuplicationProbe { %s }" % body)
        result = self._classify_amplification(
            client, resp, baseline, "field duplication"
        )
        result.evidence["duplicate_count"] = count
        return result


class DirectiveOverloadingCheck(Check):
    """A field annotated with a huge number of directives.

    Repeating built-in directives (``@include`` / ``@skip``) thousands of times
    forces the validator/parser to do work proportional to the directive count
    (CVE-2024-47614). A token/complexity limit stops this.
    """

    name = "directive-overloading"
    vector = "Directive overloading"
    severity = Severity.MEDIUM
    remediation = (
        "Limit the number of directives per field and enforce an overall query "
        "token/length limit before validation."
    )

    def run(self, client: GraphQLClient, baseline: float) -> CheckResult:
        count = self._scaled(low=200, medium=1000, high=5000)
        directives = " ".join(
            "@skip(if: false)" if i % 2 else "@include(if: true)"
            for i in range(count)
        )
        resp = client.query("query GdosDirectiveProbe { __typename %s }" % directives)

        # ``@skip``/``@include`` are not repeatable, so a spec-compliant
        # validator refuses this document on the uniqueness rule alone. That
        # rejection happens regardless of any directive-count limit, so it
        # neither proves nor disproves resilience to this vector.
        if rejected_as_duplicate_directive(resp):
            result = self._result(
                Verdict.INCONCLUSIVE,
                "Server rejected the document under the spec's unique-directive "
                "rule before any directive-count limit could apply, so this "
                "vector could not be isolated. The parser still had to read all "
                f"{count} directives; verify a query token/length limit exists.",
                resp,
                baseline,
                severity=Severity.LOW,
            )
        else:
            result = self._classify_amplification(
                client, resp, baseline, "directive overloading"
            )
        result.evidence["directive_count"] = count
        return result


class QueryDepthCheck(Check):
    """Deeply nested query via the universal ``__type.ofType`` chain.

    ``ofType`` is a nullable self-referential field on ``__Type`` present on
    every server, so it provides a schema-agnostic way to build an arbitrarily
    deep selection set. A maximum-depth rule should reject it.
    """

    name = "query-depth"
    vector = "Query depth (deep nesting)"
    severity = Severity.HIGH
    remediation = (
        "Enforce a maximum query depth (e.g. graphql-depth-limit, envelop "
        "max-depth) so deeply nested selection sets are rejected before execution."
    )

    def _build(self, depth: int) -> str:
        inner = "kind name"
        for _ in range(depth):
            inner = "kind name ofType { %s }" % inner
        return 'query GdosDepthProbe { __type(name: "String") { %s } }' % inner

    def run(self, client: GraphQLClient, baseline: float) -> CheckResult:
        depth = self._scaled(low=30, medium=100, high=300)
        resp = client.query(self._build(depth))
        result = self._classify_amplification(client, resp, baseline, "deep nesting")
        result.evidence["nesting_depth"] = depth
        return result
