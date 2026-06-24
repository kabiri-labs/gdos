# GDoS — GraphQL DoS Resilience Scanner

GDoS audits a GraphQL endpoint for **Denial-of-Service (DoS) amplification
vulnerabilities** and reports whether the server enforces the protections a
production deployment needs. Its purpose is *defensive*: to give security
engineers and developers confidence that their GraphQL API **cannot** be
trivially knocked over by a single malicious query.

Unlike a flooding tool, GDoS sends **bounded, single-shot probes** — one
crafted request per attack vector — and classifies the server's response as
`PROTECTED`, `VULNERABLE`, `INCONCLUSIVE`, or `ERROR`. It never loops, never
escalates automatically, and always honours a hard per-request timeout.

> ⚠️ **Authorized use only.** GDoS sends deliberately abusive (but bounded)
> payloads. Only run it against endpoints you own or are explicitly authorized
> to test.

## Attack vectors checked

| Vector | What it tests | A hardened server should… |
| --- | --- | --- |
| **Schema introspection exposure** | Whether the full schema is readable | Disable introspection in production |
| **Query depth (deep nesting)** | Deeply nested selection sets | Reject queries past a max depth |
| **Recursive introspection** | Nested `fields → type → fields` introspection | Bound depth/complexity, even for introspection |
| **Alias-based amplification** | Hundreds/thousands of aliases of one field | Enforce an alias-count / node limit |
| **Field duplication** | The same field repeated many times | Count duplicates in a complexity budget |
| **Directive overloading** | A field annotated with thousands of directives | Limit directives / query token length |
| **Array request batching** | A JSON array of many operations in one request | Cap or disable batch size |
| **Circular fragment spread** | A self-referential fragment (spec-forbidden) | Reject during validation |

The probes rely only on the universal GraphQL meta-fields (`__typename`,
`__type`, `__schema`), so they work against **any** spec-compliant endpoint
without prior knowledge of its schema.

## How a verdict is reached

1. GDoS first measures a **baseline** round-trip with a trivial query.
2. Each check sends its abusive probe and inspects the result:
   - A validation/limit error (e.g. *"query depth exceeds maximum"*), a `429`,
     or a rejected batch → **PROTECTED**.
   - The probe being accepted and executed, a `5xx`, a timeout, or a response
     significantly slower than the baseline → **VULNERABLE**.
   - Anything ambiguous (auth required, unexpected shape) → **INCONCLUSIVE**.

## Requirements

- Python 3.10+
- `requests`

```bash
pip install -r requirements.txt
# or install as a package (provides the `gdos` command):
pip install -e .
```

## Usage

```bash
python -m gdos https://api.example.com/graphql
# or, if installed:
gdos https://api.example.com/graphql
```

### Common options

```text
positional:
  url                     GraphQL endpoint URL

options:
  -H, --header 'K: V'     extra HTTP header (repeatable)
  --token TOKEN           shortcut for 'Authorization: Bearer <token>'
  --intensity {low,medium,high}
                          probe magnitude (depth/alias/batch sizes). Default: medium
  --timeout SECONDS       per-request timeout (default: 15)
  --baseline-samples N    warm-up requests for the baseline (default: 3)
  --insecure              disable TLS verification (not recommended)
  --json                  emit a machine-readable JSON report
  --no-color              plain text output
  -v, --verbose           progress logging
  -y, --yes               acknowledge the authorization notice (for non-interactive use)
```

### Examples

```bash
# Authenticated scan, high intensity, human-readable report
python -m gdos https://api.example.com/graphql \
  --token "$API_TOKEN" --intensity high --yes

# CI gate: JSON output, non-zero exit if any vulnerability is found
python -m gdos https://api.example.com/graphql --yes --json > report.json
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No DoS exposure detected |
| `1` | At least one vulnerability found |
| `2` | Bad arguments |
| `3` | Authorization not confirmed |

This makes GDoS easy to wire into CI to **fail a build** when a GraphQL service
regresses on its DoS protections.

## Project layout

```
gdos/
  client.py        # bounded, timeout-aware GraphQL HTTP client
  scanner.py       # baseline measurement + check orchestration
  reporting.py     # text / JSON report rendering
  cli.py           # argparse command-line interface
  checks/          # one module per attack vector
    base.py        # Check base class + verdict classification
    introspection.py
    amplification.py
    batching.py
tests/             # unit tests for the classification logic (no network needed)
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT — see [LICENSE](LICENSE).
