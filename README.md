# GDoS — GraphQL DoS Resilience Scanner

GDoS audits a GraphQL endpoint for **Denial-of-Service (DoS) amplification
vulnerabilities** and reports whether the server enforces the protections a
production deployment needs. Its purpose is *defensive*: to give security
engineers and developers confidence that their GraphQL API **cannot** be
trivially knocked over by a single malicious query.

Unlike a flooding tool, GDoS sends **bounded, single-shot probes** — normally
one crafted request per attack vector, plus a trivial control query when a
result needs confirming — and classifies the server's response as `PROTECTED`,
`VULNERABLE`, `INCONCLUSIVE`, or `ERROR`. It never loops, never raises the
magnitude of a payload, and always honours a hard per-request timeout.

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
| **Directive overloading** | A field annotated with thousands of directives, in both documented shapes | Limit directives / query token length |
| **Array request batching** | A JSON array of many operations in one request | Cap or disable batch size |
| **Circular fragment spread** | A self-referential fragment (spec-forbidden) | Reject during validation |

The probes rely only on the universal GraphQL meta-fields (`__typename`,
`__type`, `__schema`), so they work against **any** spec-compliant endpoint
without prior knowledge of its schema.

### Related CVEs

These vectors are not theoretical. Mainstream GraphQL server libraries have
shipped, and patched, several of them:

| CVE | Package | Fixed in | The vector |
| --- | --- | --- | --- |
| [CVE-2023-28867](https://osv.dev/vulnerability/CVE-2023-28867) | `graphql-java` | 17.5, 18.4, 19.4, 20.1 | Stack consumption from a crafted deeply nested query |
| [RUSTSEC-2022-0037](https://rustsec.org/advisories/RUSTSEC-2022-0037.html) | `async-graphql` | 4.0.6 | Stack overflow from deeply nested fragments |
| [CVE-2024-40094](https://osv.dev/vulnerability/CVE-2024-40094) | `graphql-java` | 19.11, 20.9, 21.5 | Crafted introspection queries slip past the DoS guard |
| [CVE-2022-37734](https://github.com/advisories/GHSA-v62j-cxhh-fq22) | `graphql-java` | 17.4, 18.3, 19.0 | CPU exhaustion from a query carrying a huge number of directives |
| [CVE-2024-47614](https://github.com/advisories/GHSA-5gc2-7c65-8fq8) | `async-graphql` | 7.0.10 | No limit on directives per field; one directive repeated millions of times |
| [CVE-2023-26144](https://osv.dev/vulnerability/CVE-2023-26144) | `graphql` (npm) | 16.8.1 | `OverlappingFieldsCanBeMergedRule` lacks guards on large queries |

Mapped onto the checks above: deep nesting covers CVE-2023-28867 and
RUSTSEC-2022-0037, recursive introspection covers CVE-2024-40094, and field
duplication covers CVE-2023-26144.

Directive overloading covers both of its CVEs, because they are 2 different
payload shapes and a server can be resilient to one and not the other.
CVE-2024-47614 is one *non-repeatable* directive stacked on a field thousands
of times; CVE-2022-37734 is thousands of *distinct non-existent* directive
names. The first shape is refused early by any spec-compliant validator under
the "Directives Are Unique Per Location" rule — before a directive-count limit
is ever consulted — so when GDoS sees that rule fire it re-probes with the
second shape, which carries no repeats and therefore cannot be dismissed the
same way. This is the only vector that may cost a second request.

The remaining 4 vectors carry no canonical library CVE, for 2 different
reasons. **Alias-based amplification**, **array request batching** and **schema
introspection exposure** are not implementation bugs at all — they are
defaults. A server that permits unlimited aliases, accepts unbounded batches or
serves its full schema is behaving exactly as written. **Circular fragment
spread** is the opposite case: rejecting it is mandatory under the GraphQL
spec, so a server that executes one has a broken validation phase rather than a
catalogued vulnerability.

Either way, patching a dependency does not close them, which is why GDoS probes
for all 8 vectors directly instead of fingerprinting versions.

## How a verdict is reached

1. GDoS measures a **baseline** round-trip with a trivial query. Only healthy
   samples count toward the median; if none succeed, the endpoint is not
   scannable and the scan stops there.
2. Each check sends its abusive probe and inspects the result:
   - The payload was **refused** by a depth/complexity/alias/batch limit, by a
     request-size limit (`413`/`414`/`431`), or during validation before
     execution → **PROTECTED**.
   - The payload was **executed** — data came back, or the server returned
     `5xx`, timed out, or answered far slower than baseline → **VULNERABLE**.
     The last 3 are confirmed against a control query first (see below).
   - The payload was **refused, but slowly** → **VULNERABLE**. A parser or
     validator that burns CPU working through the payload before rejecting it
     can be driven just as hard as one that executes it; that is precisely
     CVE-2022-37734.
   - The endpoint never exercised its DoS controls — an authentication wall, a
     throttle, a degraded or unreachable endpoint, an unexpected shape →
     **INCONCLUSIVE**.
   - The probe could not be delivered at all → **ERROR**.

### The control probe

A timeout, a `5xx`, a `429` or an unexpected slowdown is ambiguous on its own:
it may be the payload exhausting the server, or the server and network being in
that state anyway. After any such outcome GDoS sends one trivial **control
query** and decides from the contrast:

| Probe outcome | Control query succeeds | Control query also fails |
| --- | --- | --- |
| Timed out | **VULNERABLE** — the payload specifically exhausted it | **INCONCLUSIVE**, scan aborted |
| `5xx` | **VULNERABLE** — the payload reached execution | **INCONCLUSIVE**, scan aborted |
| `429` | **PROTECTED** — a cost-aware rate limit refused it | **INCONCLUSIVE**, scan aborted |
| Slow | **VULNERABLE** — trivial queries stayed fast | **INCONCLUSIVE**, scan aborted |

One case sits between the columns: a control query that still answers but is
*itself* slow means the endpoint or network is degraded across the board. The
slowdown cannot be blamed on the payload, so the verdict is **INCONCLUSIVE** —
but the endpoint is alive, so the scan continues.

Aborting matters in both directions: it keeps a scan from recording further
verdicts that merely reflect a tripped rate limiter or a downed host, and it
stops GDoS from continuing to probe an endpoint that is already unwell. An
aborted scan is always inconclusive, even if the checks that ran before it
came back `PROTECTED`, because the vectors after the abort were never probed.

### What is *not* treated as protection

- **An authentication failure is not a hardened endpoint.** A target that
  rejects probes with `401`/`403`, or with a message like *"you are not
  authorized to access this resource"* on an HTTP `200`, reports
  `INCONCLUSIVE`, not `PROTECTED`.
- **A served response is never keyword-matched.** Schema and data vocabulary
  such as `nodes`, `rateLimit` or `maximum` appears in perfectly ordinary
  results; only GraphQL `errors` messages (or the body of a non-2xx response,
  for proxy and WAF pages) are read as a rejection reason.
- **HTTP 200 is not execution.** Servers such as graphql-yoga answer validation
  failures with `200` and an `errors` array. A verdict of `VULNERABLE` requires
  evidence the payload actually ran.
- **An array of errors is not a batch of results.** The batching check counts
  the entries that carry `data`, not the length of the returned array.

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
  --delay SECONDS         pause between checks, so the scan does not trip the
                          target's rate limiter (default: 0.5)
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

# CI gate: JSON output. Exits 1 if anything is vulnerable, 4 if the scan
# could not reach a conclusion, 0 only for a conclusive clean result.
python -m gdos https://api.example.com/graphql --yes --json > report.json
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan conclusive, no DoS exposure detected |
| `1` | At least one vulnerability found |
| `2` | Bad arguments |
| `3` | Authorization not confirmed |
| `4` | Scan inconclusive — nothing was proved either way |

This makes GDoS easy to wire into CI to **fail a build** when a GraphQL service
regresses on its DoS protections.

Exit code `4` is the difference between *"this endpoint is hardened"* and
*"this endpoint never let us ask"*. A scan that hit an authentication wall, was
throttled, found the endpoint unreachable, or was aborted part-way through
produces no conclusive verdict, so it exits `4` rather than `0` — a pipeline
that treats any non-zero code as a failure will not go green on a scan that
never happened.

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
