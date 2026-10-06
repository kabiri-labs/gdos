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
from gdos.checks.base import Check, CheckResult, Rejection, Severity, Verdict
from gdos.checks.batching import BatchingCheck, CircularFragmentCheck
from gdos.checks.introspection import (
    DeepIntrospectionCheck,
    IntrospectionEnabledCheck,
)
from gdos.checks.persisted import PersistedQueryCheck
from gdos.checks.transport import (
    FieldSuggestionCheck,
    GetMethodCheck,
    IncrementalDeliveryCheck,
)

ALL_CHECKS: tuple[type[Check], ...] = (
    # Cheapest first: the surface checks are single small requests.
    IntrospectionEnabledCheck,
    FieldSuggestionCheck,
    PersistedQueryCheck,
    GetMethodCheck,
    # Then the amplification payloads.
    QueryDepthCheck,
    DeepIntrospectionCheck,
    AliasOverloadingCheck,
    FieldDuplicationCheck,
    DirectiveOverloadingCheck,
    IncrementalDeliveryCheck,
    BatchingCheck,
    CircularFragmentCheck,
)

__all__ = [
    "ALL_CHECKS",
    "Check",
    "CheckResult",
    "Rejection",
    "Severity",
    "Verdict",
    "AliasOverloadingCheck",
    "BatchingCheck",
    "CircularFragmentCheck",
    "DeepIntrospectionCheck",
    "DirectiveOverloadingCheck",
    "FieldDuplicationCheck",
    "FieldSuggestionCheck",
    "GetMethodCheck",
    "IncrementalDeliveryCheck",
    "IntrospectionEnabledCheck",
    "PersistedQueryCheck",
    "QueryDepthCheck",
]
