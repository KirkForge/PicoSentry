import json
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any


@dataclass
class Metric:
    name: str
    value: float
    labels: dict[str, str]
    timestamp: float
    metric_type: str = "gauge"  # gauge, counter, histogram, summary

class MetricsCollector:

    def __init__(self):
        self.metrics: dict[str, list[Metric]] = defaultdict(list)
        self.counters: dict[str, float] = defaultdict(float)
        self._lock = threading.Lock()
        self._start_time = time.time()

    def gauge(self, name: str, value: float, labels: dict[str, str] | None = None):
        with self._lock:
            self.metrics[name].append(Metric(
                name=name,
                value=value,
                labels=labels or {},
                timestamp=time.time(),
                metric_type="gauge"
            ))

            if len(self.metrics[name]) > 1000:
                self.metrics[name] = self.metrics[name][-1000:]

    def counter(self, name: str, increment: float = 1.0, labels: dict[str, str] | None = None):
        with self._lock:
            key = f"{name}:{json.dumps(labels or {}, sort_keys=True)}"
            self.counters[key] += increment
            self.metrics[name].append(Metric(
                name=name,
                value=self.counters[key],
                labels=labels or {},
                timestamp=time.time(),
                metric_type="counter"
            ))

    def histogram(self, name: str, value: float, labels: dict[str, str] | None = None):
        with self._lock:
            self.metrics[name].append(Metric(
                name=name,
                value=value,
                labels=labels or {},
                timestamp=time.time(),
                metric_type="histogram"
            ))

    def project_run(self, project_id: str, duration: float, status: str):
        self.counter("project_runs_total", 1, {"project": project_id, "status": status})
        self.histogram("project_duration_seconds", duration, {"project": project_id})

        if status == "completed":
            self.counter("project_success_total", 1, {"project": project_id})
        elif status == "failed":
            self.counter("project_failures_total", 1, {"project": project_id})

    def api_request(self, method: str, endpoint: str, status_code: int, duration: float):
        self.counter("api_requests_total", 1, {
            "method": method,
            "endpoint": endpoint,
            "status": str(status_code)
        })
        self.histogram("api_request_duration_seconds", duration, {
            "method": method,
            "endpoint": endpoint
        })

    def threat_level(self, score: float):
        self.gauge("threat_score", score)

    def uptime_seconds(self) -> float:
        return time.time() - self._start_time

    def to_prometheus(self) -> str:
        lines = []


        lines.append("# HELP picoshogun_uptime_seconds Total uptime in seconds")
        lines.append("# TYPE picoshogun_uptime_seconds gauge")
        lines.append(f"picoshogun_uptime_seconds {self.uptime_seconds()}")

        with self._lock:

            grouped = defaultdict(list)
            for _name, metrics_list in self.metrics.items():
                for m in metrics_list:
                    grouped[m.name].append(m)

            for name, metrics_list in sorted(grouped.items()):
                if not metrics_list:
                    continue

                metric_type = metrics_list[0].metric_type
                lines.append(f"# HELP picoshogun_{name} {metric_type} metric")
                lines.append(f"# TYPE picoshogun_{name} {metric_type}")

                for m in metrics_list[-50:]:  # Last 50 per metric
                    label_str = ",".join(f'{k}="{v}"' for k, v in m.labels.items())
                    if label_str:
                        lines.append(f'picoshogun_{name}{{{label_str}}} {m.value}')
                    else:
                        lines.append(f'picoshogun_{name} {m.value}')

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            metrics_data: dict[str, Any] = {}
            for name, metrics_list in self.metrics.items():
                metrics_data[name] = [
                    {
                        "value": m.value,
                        "labels": m.labels,
                        "timestamp": m.timestamp,
                        "type": m.metric_type
                    }
                    for m in metrics_list[-100:]
                ]

        return {
            "uptime_seconds": self.uptime_seconds(),
            "metrics": metrics_data,
            "counters": dict(self.counters)
        }


metrics = MetricsCollector()
