"""Scan orchestration: establish a baseline, run each check, collect results."""

from __future__ import annotations

import logging
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone

from gdos.checks import ALL_CHECKS
from gdos.checks.base import Check, CheckResult, Severity, Verdict
from gdos.client import GraphQLClient

log = logging.getLogger("gdos")

_BASELINE_QUERY = "query GdosBaseline { __typename }"


@dataclass
class ScanReport:
    url: str
    started_at: str
    finished_at: str
    baseline_seconds: float
    results: list[CheckResult] = field(default_factory=list)

    @property
    def vulnerable(self) -> list[CheckResult]:
        return [r for r in self.results if r.verdict is Verdict.VULNERABLE]

    @property
    def is_vulnerable(self) -> bool:
        return bool(self.vulnerable)

    def counts(self) -> dict[str, int]:
        out = {v.value: 0 for v in Verdict}
        for r in self.results:
            out[r.verdict.value] += 1
        return out


class Scanner:
    """Runs the configured set of checks against a single endpoint."""

    def __init__(
        self,
        client: GraphQLClient,
        intensity: str = "medium",
        checks: tuple[type[Check], ...] = ALL_CHECKS,
        baseline_samples: int = 3,
    ) -> None:
        self.client = client
        self.intensity = intensity
        self.checks = checks
        self.baseline_samples = max(1, baseline_samples)

    def _measure_baseline(self) -> float:
        """Median round-trip of a trivial query, used to detect slow probes."""
        samples: list[float] = []
        for _ in range(self.baseline_samples):
            resp = self.client.query(_BASELINE_QUERY)
            if resp.error and not resp.timed_out:
                log.warning("Baseline request failed: %s", resp.error)
            samples.append(resp.elapsed)
        baseline = statistics.median(samples)
        log.info("Baseline response time: %.3fs (median of %d)", baseline, len(samples))
        return baseline

    def run(self) -> ScanReport:
        started = datetime.now(timezone.utc)
        log.info("Probing baseline for %s", self.client.url)
        baseline = self._measure_baseline()

        results: list[CheckResult] = []
        for check_cls in self.checks:
            check = check_cls(intensity=self.intensity)
            log.info("Running check: %s", check.name)
            try:
                result = check.run(self.client, baseline)
            except Exception as exc:  # defensive: a check must never abort the scan
                log.exception("Check %s crashed", check.name)
                result = CheckResult(
                    name=check.name,
                    vector=check.vector,
                    verdict=Verdict.ERROR,
                    severity=Severity.INFO,
                    summary=f"Check raised an unexpected error: {exc}",
                    remediation=check.remediation,
                )
            log.info("  -> %s (%s)", result.verdict.value, result.severity.value)
            results.append(result)

        finished = datetime.now(timezone.utc)
        return ScanReport(
            url=self.client.url,
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            baseline_seconds=baseline,
            results=results,
        )
