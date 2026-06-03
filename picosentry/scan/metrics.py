"""
Observability metrics for PicoSentry.

Provides lightweight counters and histograms for monitoring scan throughput,
rule hit rates, and verdict distributions. Exportable as JSON for Prometheus
or any metrics collector via `picosentry daemon` or CLI flag.

Design: zero-dependency, in-process counters. No Prometheus client library needed.
Export via `picosentry metrics` or HTTP endpoint in daemon mode.

Usage:
    from picosentry.scan.metrics import get_metrics, increment, observe

    increment("scans.total")
    observe("scans.duration_ms", 150)
    print(get_metrics().to_json())
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger("picosentry.metrics")


@dataclass
class MetricsRegistry:
    """Thread-safe metrics registry with counters and histograms."""

    MAX_HISTOGRAM_OBSERVATIONS = 10000  # Cap per metric to bound memory

    counters: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    histograms: dict[str, list[int]] = field(default_factory=lambda: defaultdict(list))
    gauges: dict[str, float] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _start_time: float = field(default_factory=time.monotonic)

    def increment(self, name: str, value: int = 1, labels: dict[str, str] | None = None) -> None:
        """Increment a counter."""
        with self._lock:
            self.counters[name] += value
            if labels:
                for k, v in labels.items():
                    self.counters[f"{name}.{k}.{v}"] += value

    def observe(self, name: str, value: int) -> None:
        """Record a histogram observation.

        Caps at MAX_HISTOGRAM_OBSERVATIONS per metric to bound memory.
        When the cap is reached, the oldest half of observations are dropped.
        """
        with self._lock:
            hist = self.histograms[name]
            hist.append(value)
            if len(hist) > self.MAX_HISTOGRAM_OBSERVATIONS:
                # Drop oldest half to amortize the trimming cost
                self.histograms[name] = hist[len(hist) // 2 :]

    def set_gauge(self, name: str, value: float) -> None:
        """Set a gauge value."""
        with self._lock:
            self.gauges[name] = value

    def set_label(self, key: str, value: str) -> None:
        """Set a metadata label."""
        with self._lock:
            self.labels[key] = value

    def snapshot(self) -> MetricsSnapshot:
        """Take an atomic snapshot of all metrics."""
        with self._lock:
            return MetricsSnapshot(
                counters=dict(self.counters),
                histograms={k: list(v) for k, v in self.histograms.items()},
                gauges=dict(self.gauges),
                labels=dict(self.labels),
                uptime_seconds=time.monotonic() - self._start_time,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )


@dataclass
class MetricsSnapshot:
    """Immutable snapshot of metrics at a point in time."""

    counters: dict[str, int]
    histograms: dict[str, list[int]]
    gauges: dict[str, float]
    labels: dict[str, str]
    uptime_seconds: float
    timestamp: str

    def to_dict(self) -> dict:
        """Convert to a dict suitable for JSON export."""
        histogram_stats = {}
        for name, values in self.histograms.items():
            if not values:
                continue
            sorted_vals = sorted(values)
            n = len(sorted_vals)
            histogram_stats[name] = {
                "count": n,
                "sum": sum(values),
                "min": sorted_vals[0],
                "max": sorted_vals[-1],
                "p50": sorted_vals[n // 2],
                "p95": sorted_vals[int(n * 0.95)],
                "p99": sorted_vals[int(n * 0.99)],
                "avg": sum(values) / n if n > 0 else 0,
            }

        return {
            "timestamp": self.timestamp,
            "uptime_seconds": round(self.uptime_seconds, 3),
            "counters": dict(self.counters),
            "histograms": histogram_stats,
            "gauges": dict(self.gauges),
            "labels": dict(self.labels),
        }

    def to_json(self) -> str:
        """Export as JSON string."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def to_prometheus(self) -> str:
        """Export as Prometheus text format."""
        lines = []

        # Help text
        lines.append("# HELP picosentry_info Metadata about the PicoSentry instance")
        lines.append("# TYPE picosentry_info gauge")
        for k, v in self.labels.items():
            lines.append(f'picosentry_info{{key="{k}"}} {v}')

        # Counters
        for name, value in self.counters.items():
            safe_name = name.replace(".", "_").replace("-", "_")
            lines.append(f"# HELP picosentry_{safe_name} Counter for {name}")
            lines.append(f"# TYPE picosentry_{safe_name} counter")
            lines.append(f"picosentry_{safe_name} {value}")

        # Histograms
        for name, stats in self.to_dict().get("histograms", {}).items():
            safe_name = name.replace(".", "_").replace("-", "_")
            lines.append(f"# HELP picosentry_{safe_name} Histogram for {name}")
            lines.append(f"# TYPE picosentry_{safe_name} summary")
            for stat_key in ("count", "sum", "min", "max", "p50", "p95", "p99", "avg"):
                lines.append(f'picosentry_{safe_name}{{quantile="{stat_key}"}} {stats[stat_key]}')

        return "\n".join(lines) + "\n"


# ── Global metrics registry ─────────────────────────────────────────────

_global_registry: MetricsRegistry | None = None
_global_lock = threading.Lock()


def get_metrics() -> MetricsRegistry:
    """Get or create the global metrics registry."""
    global _global_registry
    with _global_lock:
        if _global_registry is None:
            _global_registry = MetricsRegistry()
            from picosentry import __version__

            _global_registry.set_label("version", __version__)
            _global_registry.set_label("service", "picosentry")
        return _global_registry


def reset_metrics() -> None:
    """Reset the global metrics registry (for testing)."""
    global _global_registry
    with _global_lock:
        _global_registry = None


def increment(name: str, value: int = 1, labels: dict[str, str] | None = None) -> None:
    """Increment a counter in the global registry."""
    get_metrics().increment(name, value, labels)


def observe(name: str, value: int) -> None:
    """Record a histogram observation."""
    get_metrics().observe(name, value)


def set_gauge(name: str, value: float) -> None:
    """Set a gauge value."""
    get_metrics().set_gauge(name, value)


# ── Predefined metric names ─────────────────────────────────────────────

METRIC_SCANS_TOTAL = "scans.total"
METRIC_SCANS_BY_VERDICT = "scans.by_verdict"
METRIC_SCANS_BY_RULE = "scans.by_rule"
METRIC_SCANS_DURATION_MS = "scans.duration_ms"
METRIC_FINDINGS_TOTAL = "findings.total"
METRIC_FINDINGS_BY_SEVERITY = "findings.by_severity"
METRIC_PACKAGES_SCANNED = "packages.scanned"
METRIC_RULE_EXECUTIONS = "rules.executions"
METRIC_CACHE_HITS = "cache.hits"
METRIC_CACHE_MISSES = "cache.misses"
METRIC_CACHE_SIZE_BYTES = "cache.size_bytes"
METRIC_CACHE_ENTRIES = "cache.entries"
METRIC_CACHE_ERRORS = "cache.errors"
METRIC_AUTH_REQUESTS = "auth.requests"
METRIC_AUTH_FAILURES = "auth.failures"
METRIC_DAEMON_ACTIVE_REQUESTS = "daemon.active_requests"
METRIC_DAEMON_RATE_LIMITED = "daemon.rate_limited"
METRIC_DAEMON_START = "daemon.start"
METRIC_DAEMON_STOP = "daemon.stop"
METRIC_ERRORS_TOTAL = "errors.total"
