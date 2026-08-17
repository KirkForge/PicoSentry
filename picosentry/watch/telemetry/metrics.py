from __future__ import annotations

import re
import threading

# Label values arrive from request context (e.g. context.model) — strip
# characters that break key round-tripping or the exposition format.
_LABEL_UNSAFE = re.compile(r'[\\",\n\r{}]')


class PrometheusMetrics:
    def __init__(self) -> None:
        self._counters: dict[str, float] = {}
        self._gauges: dict[str, float] = {}
        self._histograms: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def inc_counter(self, name: str, value: float = 1.0, labels: dict[str, str] | None = None) -> None:
        key = self._make_key(name, labels)
        with self._lock:
            self._counters[key] = self._counters.get(key, 0.0) + value

    def set_gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = self._make_key(name, labels)
        with self._lock:
            self._gauges[key] = value

    def observe_histogram(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = self._make_key(name, labels)
        with self._lock:
            if key not in self._histograms:
                self._histograms[key] = []
            self._histograms[key].append(value)

    def render(self) -> str:
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            histograms = {key: list(values) for key, values in self._histograms.items()}
        lines: list[str] = []

        for key, value in sorted(counters.items()):
            name, labels = self._parse_key(key)
            lines.append(f"# HELP {name} {name}")
            lines.append(f"# TYPE {name} counter")
            if labels:
                label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
                lines.append(f"{name}{{{label_str}}} {value}")
            else:
                lines.append(f"{name} {value}")

        for key, value in sorted(gauges.items()):
            name, labels = self._parse_key(key)
            lines.append(f"# HELP {name} {name}")
            lines.append(f"# TYPE {name} gauge")
            if labels:
                label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
                lines.append(f"{name}{{{label_str}}} {value}")
            else:
                lines.append(f"{name} {value}")

        DEFAULT_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
        for key, observations in sorted(histograms.items()):
            name, labels = self._parse_key(key)
            lines.append(f"# HELP {name} {name}")
            lines.append(f"# TYPE {name} histogram")
            label_suffix = ""
            if labels:
                label_suffix = "{" + ",".join(f'{k}="{v}"' for k, v in sorted(labels.items())) + "}"
            count = len(observations)
            total = sum(observations)
            lines.append(f"{name}_count{label_suffix} {count}")
            lines.append(f"{name}_sum{label_suffix} {total:.6f}")

            for bucket in DEFAULT_BUCKETS:
                bucket_count = sum(1 for o in observations if o <= bucket)
                if labels:
                    label_extra = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
                    lines.append(f'{name}_bucket{{le="{bucket}",{label_extra}}} {bucket_count}')
                else:
                    lines.append(f'{name}_bucket{{le="{bucket}"}} {bucket_count}')

            if labels:
                label_extra = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
                lines.append(f'{name}_bucket{{le="+Inf",{label_extra}}} {count}')
            else:
                lines.append(f'{name}_bucket{{le="+Inf"}} {count}')

        return "\n".join(lines) + "\n"

    @staticmethod
    def _make_key(name: str, labels: dict[str, str] | None) -> str:
        if not labels:
            return name
        label_str = ",".join(f"{k}={_LABEL_UNSAFE.sub('_', v)}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    @staticmethod
    def _parse_key(key: str) -> tuple[str, dict[str, str] | None]:
        if "{" not in key:
            return key, None
        name = key.split("{", maxsplit=1)[0]
        label_str = key.split("{")[1].rstrip("}")
        labels = {}
        for pair in label_str.split(","):
            k, v = pair.split("=", 1)
            labels[k] = v
        return name, labels
