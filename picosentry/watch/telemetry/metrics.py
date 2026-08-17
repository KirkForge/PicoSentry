from __future__ import annotations

import re
import threading

# Label values arrive from request context (e.g. context.model) — strip
# characters that break key round-tripping or the exposition format.
_LABEL_UNSAFE = re.compile(r'[\\",\n\r{}]')


DEFAULT_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


class _HistogramState:
    """Fixed-bucket histogram accumulator (WO4.0.0-016).

    Replaces the former append-every-observation list, which grew without bound
    and made every scrape O(total observations). Bucket boundaries are the same
    DEFAULT_BUCKETS the old renderer used, so exposition output is identical.
    """

    __slots__ = ("bucket_counts", "count", "total")

    def __init__(self) -> None:
        self.bucket_counts = [0] * len(DEFAULT_BUCKETS)
        self.count = 0
        self.total = 0.0

    def observe(self, value: float) -> None:
        self.count += 1
        self.total += value
        for i, edge in enumerate(DEFAULT_BUCKETS):
            if value <= edge:
                self.bucket_counts[i] += 1


class PrometheusMetrics:
    def __init__(self) -> None:
        self._counters: dict[str, float] = {}
        self._gauges: dict[str, float] = {}
        self._histograms: dict[str, _HistogramState] = {}
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
            state = self._histograms.get(key)
            if state is None:
                state = _HistogramState()
                self._histograms[key] = state
            state.observe(value)

    def render(self) -> str:
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            histograms = {key: (list(s.bucket_counts), s.count, s.total) for key, s in self._histograms.items()}
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

        for key, (bucket_counts, count, total) in sorted(histograms.items()):
            name, labels = self._parse_key(key)
            lines.append(f"# HELP {name} {name}")
            lines.append(f"# TYPE {name} histogram")
            label_suffix = ""
            if labels:
                label_suffix = "{" + ",".join(f'{k}="{v}"' for k, v in sorted(labels.items())) + "}"

            lines.append(f"{name}_count{label_suffix} {count}")
            lines.append(f"{name}_sum{label_suffix} {total:.6f}")

            for bucket, bucket_count in zip(DEFAULT_BUCKETS, bucket_counts, strict=True):
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
