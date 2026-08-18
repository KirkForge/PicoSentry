import json
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

# Label values arrive from request context (the endpoint label is the request's
# percent-decoded path) — strip characters that break the exposition format.
_LABEL_UNSAFE = re.compile(r'[\\",\n\r{}]')

# api families are never org-stamped (upgrade path: stamp org in
# AuditMiddleware.dispatch) — exempt from the org filter or org-filtered views
# would hide every api series.
_ORG_UNSTAMPED_FAMILIES = frozenset({"api_requests_total", "api_request_duration_seconds"})


def _format_labels(labels: dict[str, str]) -> str:
    """Single-source label renderer: sorted, escaped, injection-safe."""
    return ",".join(f'{k}="{_LABEL_UNSAFE.sub("_", str(v))}"' for k, v in sorted(labels.items()))


@dataclass
class Metric:
    name: str
    value: float
    labels: dict[str, str]
    timestamp: float
    metric_type: str = "gauge"  # gauge, counter, histogram, summary


class MetricsCollector:
    """Collects and exposes application metrics in Prometheus and dictionary formats."""

    def __init__(self):
        self.metrics: dict[str, list[Metric]] = defaultdict(list)
        self.counters: dict[str, float] = defaultdict(float)
        self.global_gauges: dict[str, float] = {}
        self._lock = threading.Lock()
        self._start_time = time.time()
        self._max_counter_keys = 1000
        self._counter_timestamps: dict[str, float] = {}

    def set_global_gauge(self, name: str, value: float) -> None:
        """Instance-wide gauge, never org-filtered (pipeline health signals)."""
        with self._lock:
            self.global_gauges[name] = value

    def gauge(self, name: str, value: float, labels: dict[str, str] | None = None):
        with self._lock:
            self.metrics[name].append(
                Metric(name=name, value=value, labels=labels or {}, timestamp=time.time(), metric_type="gauge")
            )

            if len(self.metrics[name]) > 1000:
                self.metrics[name] = self.metrics[name][-500:]

    def counter(self, name: str, increment: float = 1.0, labels: dict[str, str] | None = None):
        with self._lock:
            key = f"{name}:{json.dumps(labels or {}, sort_keys=True)}"
            self.counters[key] += increment
            self._counter_timestamps[key] = time.time()
            if len(self.counters) > self._max_counter_keys:
                oldest_keys = sorted(self._counter_timestamps, key=lambda k: self._counter_timestamps.get(k, 0))[
                    : len(self.counters) // 4
                ]
                for k in oldest_keys:
                    del self.counters[k]
                    self._counter_timestamps.pop(k, None)
            self.metrics[name].append(
                Metric(
                    name=name,
                    value=self.counters[key],
                    labels=labels or {},
                    timestamp=time.time(),
                    metric_type="counter",
                )
            )

            if len(self.metrics[name]) > 1000:
                self.metrics[name] = self.metrics[name][-500:]

    def histogram(self, name: str, value: float, labels: dict[str, str] | None = None):
        with self._lock:
            self.metrics[name].append(
                Metric(name=name, value=value, labels=labels or {}, timestamp=time.time(), metric_type="histogram")
            )

            if len(self.metrics[name]) > 1000:
                self.metrics[name] = self.metrics[name][-500:]

    def project_run(self, project_id: str, duration: float, status: str, org_id: int | None = None):
        labels = {"project": project_id}
        if org_id is not None:
            labels["org_id"] = str(org_id)
        hist_labels = {"project": project_id}
        if org_id is not None:
            hist_labels["org_id"] = str(org_id)
        self.counter("project_runs_total", 1, labels)
        self.histogram("project_duration_seconds", duration, hist_labels)

        if status == "completed":
            self.counter("project_success_total", 1, labels)
        elif status == "failed":
            self.counter("project_failures_total", 1, labels)

    def api_request(self, method: str, endpoint: str, status_code: int, duration: float):
        # status keeps the exact code; status_class ("5xx") is the label the
        # high_error_rate anomaly rule matches — exact codes would need one
        # rule per status code. The endpoint label is attacker-controlled
        # (unauthenticated paths included) — sanitized once here.
        endpoint = _LABEL_UNSAFE.sub("_", endpoint)
        labels = {
            "method": method,
            "endpoint": endpoint,
            "status": str(status_code),
            "status_class": f"{status_code // 100}xx",
        }
        self.counter("api_requests_total", 1, labels)
        self.histogram("api_request_duration_seconds", duration, {"method": method, "endpoint": endpoint})

    def threat_level(self, score: float):
        self.gauge("threat_score", score)

    def uptime_seconds(self) -> float:
        return time.time() - self._start_time

    def to_prometheus(self, org_id: int | None = None) -> str:
        lines = []

        lines.append("# HELP picoshogun_uptime_seconds Total uptime in seconds")
        lines.append("# TYPE picoshogun_uptime_seconds gauge")
        lines.append(f"picoshogun_uptime_seconds {self.uptime_seconds()}")

        for name, value in sorted(self.global_gauges.items()):
            lines.append(f"# HELP picoshogun_{name} global gauge")
            lines.append(f"# TYPE picoshogun_{name} gauge")
            lines.append(f"picoshogun_{name} {value}")

        with self._lock:
            # Aggregate by full label set at render time: exactly ONE sample
            # per series per scrape (Prometheus rejects duplicate samples).
            # Counters arrive as cumulative snapshots and gauges as current
            # state — latest wins; histogram observations accumulate (sum).
            aggregated: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
            types: dict[str, str] = {}
            for metrics_list in self.metrics.values():
                for m in metrics_list:
                    if (
                        org_id is not None
                        and m.name not in _ORG_UNSTAMPED_FAMILIES
                        and m.labels.get("org_id") != str(org_id)
                    ):
                        continue
                    key = (m.name, tuple(sorted(m.labels.items())))
                    if m.metric_type == "histogram":
                        aggregated[key] = aggregated.get(key, 0.0) + m.value
                    else:
                        aggregated[key] = m.value
                    types.setdefault(m.name, m.metric_type)

            current_name = None
            for (name, label_items), value in sorted(aggregated.items()):
                if name != current_name:
                    metric_type = types[name]
                    lines.append(f"# HELP picoshogun_{name} {metric_type} metric")
                    lines.append(f"# TYPE picoshogun_{name} {metric_type}")
                    current_name = name
                label_str = _format_labels(dict(label_items))
                if label_str:
                    lines.append(f"picoshogun_{name}{{{label_str}}} {value}")
                else:
                    lines.append(f"picoshogun_{name} {value}")

        return "\n".join(lines)

    def to_dict(self, org_id: int | None = None) -> dict[str, Any]:
        with self._lock:
            metrics_data: dict[str, Any] = {}
            counters: dict[str, float] = {}
            for name, metrics_list in self.metrics.items():
                filtered = [
                    {"value": m.value, "labels": m.labels, "timestamp": m.timestamp, "type": m.metric_type}
                    for m in metrics_list[-100:]
                    if org_id is None or m.name in _ORG_UNSTAMPED_FAMILIES or m.labels.get("org_id") == str(org_id)
                ]
                if filtered:
                    metrics_data[name] = filtered

            if org_id is None:
                counters = dict(self.counters)
            else:
                org_str = str(org_id)
                for key, value in self.counters.items():
                    if f'"org_id": "{org_str}"' in key:
                        counters[key] = value

        return {
            "uptime_seconds": self.uptime_seconds(),
            "global_gauges": dict(self.global_gauges),
            "metrics": metrics_data,
            "counters": counters,
        }


metrics = MetricsCollector()
