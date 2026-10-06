"""GDoS — GraphQL DoS resilience scanner.

A defensive security-testing tool that probes a GraphQL endpoint for known
Denial-of-Service amplification vectors (deep nesting, alias/field/directive
overloading, array batching, recursive introspection, circular fragments) and
reports whether the server enforces protective limits.

GDoS sends *bounded, single-shot* probes — it does not flood the target.
"""

from __future__ import annotations

__version__ = "2.3.0"

__all__ = ["__version__"]
