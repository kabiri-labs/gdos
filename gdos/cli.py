"""Command-line interface for the GDoS resilience scanner."""

from __future__ import annotations

import argparse
import logging
import sys

from gdos import __version__
from gdos.client import DEFAULT_MAX_RESPONSE_BYTES, GraphQLClient
from gdos.reporting import to_json, to_text
from gdos.scanner import ScanReport, Scanner

log = logging.getLogger("gdos")

_AUTHORIZATION_NOTICE = (
    "GDoS sends abusive (but bounded, single-shot) probes to the target. Only "
    "run it against endpoints you own or are explicitly authorized to test."
)


def _parse_header(values: list[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in values or []:
        if ":" not in raw:
            raise argparse.ArgumentTypeError(
                f"invalid header {raw!r}; expected 'Key: Value'"
            )
        key, value = raw.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gdos",
        description=(
            "GraphQL DoS resilience scanner — probe a GraphQL endpoint for "
            "DoS-amplification vectors and report whether protections are in place."
        ),
        epilog=_AUTHORIZATION_NOTICE,
    )
    parser.add_argument("url", help="GraphQL endpoint URL")
    parser.add_argument(
        "-H", "--header", action="append", metavar="'Key: Value'",
        help="extra HTTP header (repeatable). E.g. -H 'Authorization: Bearer ...'",
    )
    parser.add_argument(
        "--token", help="shortcut for adding an 'Authorization: Bearer <token>' header",
    )
    parser.add_argument(
        "--intensity", choices=("low", "medium", "high"), default="medium",
        help="probe magnitude (depth/alias/batch sizes). Default: medium",
    )
    parser.add_argument(
        "--timeout", type=float, default=15.0,
        help="per-request timeout in seconds (default: 15)",
    )
    parser.add_argument(
        "--baseline-samples", type=int, default=3,
        help="number of warm-up requests used to compute the baseline (default: 3)",
    )
    parser.add_argument(
        "--delay", type=float, default=0.5,
        help="seconds to wait between checks, to avoid tripping the target's "
             "rate limiter mid-scan (default: 0.5)",
    )
    parser.add_argument(
        "--max-response-bytes", type=int, default=DEFAULT_MAX_RESPONSE_BYTES,
        metavar="N",
        help="stop reading a response body after N bytes, so an amplified "
             "answer cannot exhaust the scanner. Hitting the cap is reported "
             f"as evidence, not an error (default: {DEFAULT_MAX_RESPONSE_BYTES})",
    )
    parser.add_argument(
        "--apq-register", action="store_true",
        help="allow the persisted-query check to write one entry to the "
             "target's APQ cache, which is what reveals whether the server "
             "verifies hash/document pairs. This is the only probe that "
             "changes state on the target, and it is off by default",
    )
    parser.add_argument(
        "--insecure", action="store_true",
        help="disable TLS certificate verification (not recommended)",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit a JSON report instead of text",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="disable ANSI colour in text output",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="verbose progress logging",
    )
    parser.add_argument(
        "--yes", "-y", action="store_true",
        help="acknowledge the authorization notice and skip the prompt",
    )
    parser.add_argument("--version", action="version", version=f"gdos {__version__}")
    return parser


def _confirm_authorization(url: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        log.error(
            "Refusing to run non-interactively without --yes. %s",
            _AUTHORIZATION_NOTICE,
        )
        return False
    print(_AUTHORIZATION_NOTICE)
    answer = input(f"Proceed against {url}? [y/N] ").strip().lower()
    return answer in ("y", "yes")


def exit_code(report: ScanReport) -> int:
    """Map a finished scan onto the documented process exit codes.

    ``1`` when something is vulnerable, ``4`` when the scan proved nothing
    either way, ``0`` only for a scan that actually exercised the endpoint and
    found it hardened.
    """
    if report.is_vulnerable:
        return 1
    if not report.is_conclusive:
        return 4
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
    )

    try:
        headers = _parse_header(args.header)
    except argparse.ArgumentTypeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.token:
        headers.setdefault("Authorization", f"Bearer {args.token}")

    if not _confirm_authorization(args.url, args.yes):
        print("Aborted: authorization not confirmed.", file=sys.stderr)
        return 3

    client = GraphQLClient(
        url=args.url,
        headers=headers,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        max_response_bytes=args.max_response_bytes,
    )
    try:
        scanner = Scanner(
            client,
            intensity=args.intensity,
            baseline_samples=args.baseline_samples,
            delay=args.delay,
            allow_state_changing=args.apq_register,
        )
        report = scanner.run()
    finally:
        client.close()

    if args.json:
        print(to_json(report))
    else:
        print(to_text(report, color=not args.no_color))

    # Exit non-zero when at least one vulnerability was found, so the scanner
    # can gate CI / be used in automated pipelines.
    return exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
