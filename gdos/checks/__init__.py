"""Resilience checks for GraphQL DoS vectors.

Each check probes one vector with a single bounded request and returns a
:class:`~gdos.checks.base.CheckResult`. ``ALL_CHECKS`` is the registry used by
the scanner; order is roughly cheapest-to-heaviest.
"""

from __future__ import annotations

from gdos.checks.amplification import (
    AliasOverloadingCheck,
    DirectiveOverloadingCheck,
    FieldDuplicationCheck,
    QueryDepthCheck,
)
from gdos.checks.base import Check, CheckResult, Severity, Verdict
from gdos.checks.batching import BatchingCheck, CircularFragmentCheck
from gdos.checks.introspection import (
    DeepIntrospectionCheck,
    IntrospectionEnabledCheck,
)

ALL_CHECKS: tuple[type[Check], ...] = (
    IntrospectionEnabledCheck,
    QueryDepthCheck,
    DeepIntrospectionCheck,
    AliasOverloadingCheck,
    FieldDuplicationCheck,
    DirectiveOverloadingCheck,
    BatchingCheck,
    CircularFragmentCheck,
)

__all__ = [
    "ALL_CHECKS",
    "Check",
    "CheckResult",
    "Severity",
    "Verdict",
    "AliasOverloadingCheck",
    "BatchingCheck",
    "CircularFragmentCheck",
    "DeepIntrospectionCheck",
    "DirectiveOverloadingCheck",
    "FieldDuplicationCheck",
    "IntrospectionEnabledCheck",
    "QueryDepthCheck",
]
