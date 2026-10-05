"""Scan orchestration: establish a baseline, run each check, collect results."""

from __future__ import annotations

import logging
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from gdos.checks import ALL_CHECKS
from gdos.checks.base import Check, CheckResult, Severity, Verdict, endpoint_healthy
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
    baseline_ok: bool = True
    """False when no baseline sample came back healthy — nothing below it is
    trustworthy, because every verdict is measured against that baseline."""
    baseline_samples_ok: int = 0
    aborted: bool = False
    abort_reason: str | None = None

    @property
    def vulnerable(self) -> list[CheckResult]:
        return [r for r in self.results if r.verdict is Verdict.VULNERABLE]

    @property
    def is_vulnerable(self) -> bool:
        return bool(self.vulnerable)

    @property
    def is_conclusive(self) -> bool:
        """True if the scan produced at least one verdict worth acting on.

        A scan where every check came back INCONCLUSIVE or ERROR — an auth
        wall, a throttle, a dead endpoint — proves nothing. Reporting that as
        "no DoS exposure detected" would hand a CI pipeline a false clean bill
        of health, so callers must be able to tell the two apart.
        """
        return self.baseline_ok and any(
            r.verdict in (Verdict.PROTECTED, Verdict.VULNERABLE) for r in self.results
        )

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
        delay: float = 0.5,
    ) -> None:
        self.client = client
        self.intensity = intensity
        self.checks = checks
        self.baseline_samples = max(1, baseline_samples)
        self.delay = max(0.0, delay)

    def _measure_baseline(self) -> tuple[float, int]:
        """Median round-trip of a trivial query, used to detect slow probes.

        Only healthy samples count. A failed or timed-out request contributes
        nothing: folding a 15s timeout into the median would push the
        "slower than baseline" threshold past anything a probe could reach and
        silently disable slowdown detection for the rest of the scan.
        """
        samples: list[float] = []
        for _ in range(self.baseline_samples):
            resp = self.client.query(_BASELINE_QUERY)
            if not endpoint_healthy(resp):
                log.warning(
                    "Baseline sample discarded (status=%s, timed_out=%s, error=%s)",
                    resp.status_code,
                    resp.timed_out,
                    resp.error,
                )
                continue
            samples.append(resp.elapsed)
        if not samples:
            return 0.0, 0
        baseline = statistics.median(samples)
        log.info(
            "Baseline response time: %.3fs (median of %d/%d healthy samples)",
            baseline,
            len(samples),
            self.baseline_samples,
        )
        return baseline, len(samples)

    def _unusable_endpoint(self) -> list[CheckResult]:
        reason = (
            "Endpoint did not answer the trivial baseline query. It is "
            "unreachable, behind an authentication wall, or rejecting every "
            "request — no DoS verdict can be derived from it."
        )
        return [
            CheckResult(
                name=cls.name,
                vector=cls.vector,
                verdict=Verdict.ERROR,
                severity=Severity.INFO,
                summary=reason,
                remediation=cls.remediation,
            )
            for cls in self.checks
        ]

    def _skipped(self, cls: type[Check]) -> CheckResult:
        """A check the scan never reached. The reason is on the report itself,
        so it is stated once rather than repeated under every skipped vector."""
        return CheckResult(
            name=cls.name,
            vector=cls.vector,
            verdict=Verdict.INCONCLUSIVE,
            severity=Severity.INFO,
            summary="Not run — the scan was aborted before this check.",
            remediation=cls.remediation,
        )

    def run(self) -> ScanReport:
        started = datetime.now(timezone.utc)
        log.info("Probing baseline for %s", self.client.url)
        baseline, samples_ok = self._measure_baseline()

        if samples_ok == 0:
            log.error("Baseline failed; the endpoint is not in a scannable state")
            return ScanReport(
                url=self.client.url,
                started_at=started.isoformat(),
                finished_at=datetime.now(timezone.utc).isoformat(),
                baseline_seconds=baseline,
                results=self._unusable_endpoint(),
                baseline_ok=False,
                baseline_samples_ok=0,
            )

        results: list[CheckResult] = []
        abort_reason: str | None = None
        for index, check_cls in enumerate(self.checks):
            if abort_reason is not None:
                results.append(self._skipped(check_cls))
                continue
            # Pace the scan. One abusive request per vector is still a burst,
            # and a throttle tripped mid-scan would make every later verdict
            # reflect the rate limiter instead of the endpoint's DoS controls.
            if index and self.delay:
                time.sleep(self.delay)

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
            if result.abort_scan:
                abort_reason = result.summary
                log.warning("Aborting scan after %s: %s", check.name, abort_reason)

        finished = datetime.now(timezone.utc)
        return ScanReport(
            url=self.client.url,
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            baseline_seconds=baseline,
            results=results,
            baseline_ok=True,
            baseline_samples_ok=samples_ok,
            aborted=abort_reason is not None,
            abort_reason=abort_reason,
        )
