from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("picodome.slo")


@dataclass(frozen=True)
class SLODefinition:
    name: str
    description: str
    target: float  # e.g., 0.999 for 99.9%
    unit: str = ""  # e.g., "%", "ms", "req/min"
    window_hours: int = 720  # 30 days rolling window

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "name": self.name,
            "target": self.target,
            "unit": self.unit,
            "window_hours": self.window_hours,
        }


@dataclass(frozen=True)
class SLOMeasurement:
    name: str
    measured_value: float
    target_value: float
    compliant: bool
    timestamp: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "compliant": self.compliant,
            "detail": self.detail,
            "measured_value": self.measured_value,
            "name": self.name,
            "target_value": self.target_value,
            "timestamp": self.timestamp,
        }


SLO_AVAILABILITY = SLODefinition(
    name="availability",
    description="Daemon uptime — successful health checks / total health checks",
    target=0.999,
    unit="%",
    window_hours=720,
)

SLO_LATENCY_P50 = SLODefinition(
    name="latency_p50",
    description="Scan latency at 50th percentile",
    target=500.0,
    unit="ms",
    window_hours=720,
)

SLO_LATENCY_P95 = SLODefinition(
    name="latency_p95",
    description="Scan latency at 95th percentile",
    target=2000.0,
    unit="ms",
    window_hours=720,
)

SLO_LATENCY_P99 = SLODefinition(
    name="latency_p99",
    description="Scan latency at 99th percentile",
    target=5000.0,
    unit="ms",
    window_hours=720,
)

SLO_THROUGHPUT = SLODefinition(
    name="throughput",
    description="Sustained scan throughput",
    target=10.0,
    unit="scans/min",
    window_hours=720,
)

SLO_ERROR_RATE = SLODefinition(
    name="error_rate",
    description="Scan error rate (failed / total)",
    target=0.01,
    unit="%",
    window_hours=720,
)

SLO_DETERMINISM = SLODefinition(
    name="determinism",
    description="Deterministic output on identical inputs",
    target=1.0,
    unit="%",
    window_hours=720,
)

ALL_SLOS = [
    SLO_AVAILABILITY,
    SLO_LATENCY_P50,
    SLO_LATENCY_P95,
    SLO_LATENCY_P99,
    SLO_THROUGHPUT,
    SLO_ERROR_RATE,
    SLO_DETERMINISM,
]

MAX_LATENCY_SAMPLES = 10000  # Cap memory usage for SLO latency tracking


class SLOTracker:
    def __init__(self) -> None:
        self._latency_samples: list[float] = []
        self._total_scans: int = 0
        self._failed_scans: int = 0
        self._health_checks: int = 0
        self._health_ok: int = 0
        self._determinism_checks: int = 0
        self._determinism_ok: int = 0
        self._start_time: float = time.monotonic()

    def reset(self) -> None:
        self._latency_samples.clear()
        self._total_scans = 0
        self._failed_scans = 0
        self._health_checks = 0
        self._health_ok = 0
        self._determinism_checks = 0
        self._determinism_ok = 0
        self._start_time = time.monotonic()

    def record_scan(self, duration_ms: float, success: bool) -> None:
        self._latency_samples.append(duration_ms)
        if len(self._latency_samples) > MAX_LATENCY_SAMPLES:
            self._latency_samples = self._latency_samples[-MAX_LATENCY_SAMPLES:]
        self._total_scans += 1
        if not success:
            self._failed_scans += 1

    def record_health_check(self, healthy: bool) -> None:
        self._health_checks += 1
        if healthy:
            self._health_ok += 1

    def record_determinism_check(self, passed: bool) -> None:
        self._determinism_checks += 1
        if passed:
            self._determinism_ok += 1

    def measure(self) -> list[SLOMeasurement]:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        measurements: list[SLOMeasurement] = []

        if self._health_checks > 0:
            avail = self._health_ok / self._health_checks
            measurements.append(
                SLOMeasurement(
                    name="availability",
                    measured_value=round(avail, 6),
                    target_value=SLO_AVAILABILITY.target,
                    compliant=avail >= SLO_AVAILABILITY.target,
                    timestamp=now,
                    detail=f"{self._health_ok}/{self._health_checks} healthy",
                )
            )

        if self._latency_samples:
            sorted_lat = sorted(self._latency_samples)
            p50 = sorted_lat[int(len(sorted_lat) * 0.50)]
            p95 = sorted_lat[int(len(sorted_lat) * 0.95)] if len(sorted_lat) > 1 else sorted_lat[0]
            p99 = sorted_lat[int(len(sorted_lat) * 0.99)] if len(sorted_lat) > 1 else sorted_lat[0]

            measurements.append(
                SLOMeasurement(
                    name="latency_p50",
                    measured_value=round(p50, 1),
                    target_value=SLO_LATENCY_P50.target,
                    compliant=p50 <= SLO_LATENCY_P50.target,
                    timestamp=now,
                )
            )
            measurements.append(
                SLOMeasurement(
                    name="latency_p95",
                    measured_value=round(p95, 1),
                    target_value=SLO_LATENCY_P95.target,
                    compliant=p95 <= SLO_LATENCY_P95.target,
                    timestamp=now,
                )
            )
            measurements.append(
                SLOMeasurement(
                    name="latency_p99",
                    measured_value=round(p99, 1),
                    target_value=SLO_LATENCY_P99.target,
                    compliant=p99 <= SLO_LATENCY_P99.target,
                    timestamp=now,
                )
            )

        elapsed_min = (time.monotonic() - self._start_time) / 60.0
        if elapsed_min >= 1.0:
            throughput = self._total_scans / elapsed_min
            measurements.append(
                SLOMeasurement(
                    name="throughput",
                    measured_value=round(throughput, 2),
                    target_value=SLO_THROUGHPUT.target,
                    compliant=throughput >= SLO_THROUGHPUT.target,
                    timestamp=now,
                )
            )

        if self._total_scans > 0:
            error_rate = self._failed_scans / self._total_scans
            measurements.append(
                SLOMeasurement(
                    name="error_rate",
                    measured_value=round(error_rate, 6),
                    target_value=SLO_ERROR_RATE.target,
                    compliant=error_rate <= SLO_ERROR_RATE.target,
                    timestamp=now,
                    detail=f"{self._failed_scans}/{self._total_scans} failed",
                )
            )

        if self._determinism_checks > 0:
            det_rate = self._determinism_ok / self._determinism_checks
            measurements.append(
                SLOMeasurement(
                    name="determinism",
                    measured_value=round(det_rate, 6),
                    target_value=SLO_DETERMINISM.target,
                    compliant=det_rate >= SLO_DETERMINISM.target,
                    timestamp=now,
                    detail=f"{self._determinism_ok}/{self._determinism_checks} passed",
                )
            )

        return measurements

    def get_report(self) -> dict[str, Any]:
        measurements = self.measure()
        all_compliant = all(m.compliant for m in measurements) if measurements else True

        return {
            "all_compliant": all_compliant,
            "measurements": [m.to_dict() for m in measurements],
            "slo_definitions": [s.to_dict() for s in ALL_SLOS],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_scans": self._total_scans,
        }
