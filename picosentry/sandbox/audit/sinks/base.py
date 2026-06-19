from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any

from picosentry.sandbox.audit.logger import AuditEvent

logger = logging.getLogger("picodome.audit.sink")


class SinkHealth(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"  # recent failures but still trying
    FAILED = "failed"  # permanently failed (will not retry)


@dataclass(frozen=True)
class SinkConfig:
    enabled: bool = True
    batch_size: int = 1
    flush_interval: float = 0.0
    max_retries: int = 3
    retry_backoff: float = 1.0
    timeout: float = 10.0


class AuditSink(ABC):
    def __init__(self, config: SinkConfig | None = None) -> None:
        self._config = config or SinkConfig()
        self._stats: dict[str, Any] = {
            "events_sent": 0,
            "events_failed": 0,
            "events_dropped": 0,
            "last_send_time": None,
            "last_error": None,
            "started_at": None,
        }
        self._health = SinkHealth.HEALTHY

    def start(self) -> None:
        self._stats["started_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def stop(self) -> None:
        """Release any resources held by this sink. Default no-op."""
        return

    def flush(self) -> None:
        """Flush any buffered events. Default no-op."""
        return

    @abstractmethod
    def send(self, event: AuditEvent) -> None:
        """Send an audit event to the external system.

        Must never raise. On failure, log the error and update stats.
        """

    @property
    def health(self) -> SinkHealth:
        return self._health

    @property
    def stats(self) -> dict[str, Any]:
        return dict(self._stats)

    def _record_success(self) -> None:
        self._stats["events_sent"] += 1
        self._stats["last_send_time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        if self._health == SinkHealth.DEGRADED:
            self._health = SinkHealth.HEALTHY

    def _record_failure(self, error: str) -> None:
        self._stats["events_failed"] += 1
        self._stats["last_error"] = error

        if self._stats["events_failed"] > 5:
            self._health = SinkHealth.FAILED
        elif self._health == SinkHealth.HEALTHY:
            self._health = SinkHealth.DEGRADED

    def _record_dropped(self) -> None:
        self._stats["events_dropped"] += 1

    @property
    def name(self) -> str:
        return self.__class__.__name__


class NullSink(AuditSink):
    def send(self, event: AuditEvent) -> None:
        logger.debug("NullSink: discarding event %s (%s)", event.event_id[:8], event.event_type.value)


SINK_REGISTRY: dict[str, type[AuditSink]] = {}


def register_sink(name: str, cls: type[AuditSink]) -> None:
    if name in SINK_REGISTRY:
        logger.warning("Overwriting sink registry entry for '%s'", name)
    SINK_REGISTRY[name] = cls


def create_sink(name: str, config: SinkConfig | None = None, **kwargs: Any) -> AuditSink:
    if name not in SINK_REGISTRY:
        raise ValueError(f"Unknown sink type: '{name}'. Available: {list(SINK_REGISTRY)}")
    return SINK_REGISTRY[name](config, **kwargs)
