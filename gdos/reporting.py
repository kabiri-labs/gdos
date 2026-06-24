"""Render a :class:`~gdos.scanner.ScanReport` as text or JSON."""

from __future__ import annotations

import json
from dataclasses import asdict

from gdos.checks.base import Severity, Verdict
from gdos.scanner import ScanReport

_VERDICT_GLYPH = {
    Verdict.PROTECTED: "PASS",
    Verdict.VULNERABLE: "FAIL",
    Verdict.INCONCLUSIVE: "WARN",
    Verdict.ERROR: "ERR ",
}

_SEVERITY_ORDER = {
    Severity.HIGH: 0,
    Severity.MEDIUM: 1,
    Severity.LOW: 2,
    Severity.INFO: 3,
}


def to_json(report: ScanReport) -> str:
    payload = {
        "url": report.url,
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "baseline_seconds": round(report.baseline_seconds, 4),
        "is_vulnerable": report.is_vulnerable,
        "counts": report.counts(),
        "results": [
            {
                "name": r.name,
                "vector": r.vector,
                "verdict": r.verdict.value,
                "severity": r.severity.value,
                "summary": r.summary,
                "remediation": r.remediation,
                "elapsed_seconds": round(r.elapsed, 4),
                "evidence": r.evidence,
            }
            for r in report.results
        ],
    }
    return json.dumps(payload, indent=2, default=str)


def _color(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def to_text(report: ScanReport, color: bool = True) -> str:
    verdict_color = {
        Verdict.PROTECTED: "32",   # green
        Verdict.VULNERABLE: "31",  # red
        Verdict.INCONCLUSIVE: "33",  # yellow
        Verdict.ERROR: "90",       # grey
    }
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("GDoS — GraphQL DoS Resilience Report")
    lines.append("=" * 72)
    lines.append(f"Target    : {report.url}")
    lines.append(f"Started   : {report.started_at}")
    lines.append(f"Baseline  : {report.baseline_seconds:.3f}s")
    lines.append("")

    ordered = sorted(
        report.results,
        key=lambda r: (
            0 if r.verdict is Verdict.VULNERABLE else 1,
            _SEVERITY_ORDER.get(r.severity, 9),
        ),
    )
    for r in ordered:
        tag = _color(_VERDICT_GLYPH[r.verdict], verdict_color[r.verdict], color)
        lines.append(f"[{tag}] {r.vector}  ({r.severity.value})")
        lines.append(f"       {r.summary}")
        if r.verdict is Verdict.VULNERABLE and r.remediation:
            lines.append(f"       fix: {r.remediation}")
        lines.append("")

    counts = report.counts()
    summary = (
        f"{counts[Verdict.VULNERABLE.value]} vulnerable, "
        f"{counts[Verdict.PROTECTED.value]} protected, "
        f"{counts[Verdict.INCONCLUSIVE.value]} inconclusive, "
        f"{counts[Verdict.ERROR.value]} errored"
    )
    lines.append("-" * 72)
    if report.is_vulnerable:
        lines.append(_color(f"RESULT: VULNERABLE — {summary}", "31;1", color))
    else:
        lines.append(_color(f"RESULT: no DoS exposure detected — {summary}", "32;1", color))
    lines.append("=" * 72)
    return "\n".join(lines)
