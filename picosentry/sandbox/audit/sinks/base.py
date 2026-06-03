"""Audit sink interface and null implementation.

Every sink inherits from AuditSink and implements ``send(event)``.
The ``send`` method must never raise — errors should be logged and
the sink should track its own failure stats.

SinkConfig holds the common configuration shared by all sinks.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any

from picosentry.sandbox.audit.logger import AuditEvent

logger = logging.getLogger("picodome.audit.sink")


# ─── Sink health status ────────────────────────────────────────────────────


class SinkHealth(str, Enum):
    """Health status of a sink."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"  # recent failures but still trying
    FAILED = "failed"  # permanently failed (will not retry)


# ─── Configuration ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SinkConfig:
    """Common configuration for all audit sinks.

    Attributes:
        enabled: Whether the sink is active.
        batch_size: Number of events to buffer before flushing (1 = immediate).
        flush_interval: Max seconds between flushes (0 = immediate).
        max_retries: Maximum retry attempts per event before dropping.
        retry_backoff: Base seconds for exponential backoff on retries.
        timeout: Seconds to wait for I/O operations before giving up.
    """

    enabled: bool = True
    batch_size: int = 1
    flush_interval: float = 0.0
    max_retries: int = 3
    retry_backoff: float = 1.0
    timeout: float = 10.0


# ─── Abstract base ─────────────────────────────────────────────────────────


class AuditSink(ABC):
    """Base class for all audit sinks.

    Subclasses must implement ``send(event)``.  The base class tracks
    basic statistics (events sent, failures, last send time) and
    provides a health check.

    Lifecycle:
        1. Instantiate with SinkConfig
        2. ``start()`` — open connections / files
        3. ``send(event)`` — called for each audit event
        4. ``flush()`` — ensure buffered events are written
        5. ``stop()`` — clean up resources
    """

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

    # ── Lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        """Open connections, create files, etc. Override if needed."""
        self._stats["started_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def stop(self) -> None:  # noqa: B027
        """Clean up resources. Override if needed."""
        pass

    def flush(self) -> None:  # noqa: B027
        """Flush any buffered events. Override if batching."""
        pass

    # ── Core method ─────────────────────────────────────────────────────

    @abstractmethod
    def send(self, event: AuditEvent) -> None:
        """Send an audit event to the external system.

        Must never raise. On failure, log the error and update stats.
        """

    # ── Health & stats ──────────────────────────────────────────────────

    @property
    def health(self) -> SinkHealth:
        """Current health status of this sink."""
        return self._health

    @property
    def stats(self) -> dict[str, Any]:
        """Snapshot of sink statistics."""
        return dict(self._stats)

    def _record_success(self) -> None:
        """Mark an event as successfully sent."""
        self._stats["events_sent"] += 1
        self._stats["last_send_time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        # Recover from degraded on success
        if self._health == SinkHealth.DEGRADED:
            self._health = SinkHealth.HEALTHY

    def _record_failure(self, error: str) -> None:
        """Mark an event as failed to send."""
        self._stats["events_failed"] += 1
        self._stats["last_error"] = error
        # Degrade health after failures
        if self._stats["events_failed"] > 5:
            self._health = SinkHealth.FAILED
        elif self._health == SinkHealth.HEALTHY:
            self._health = SinkHealth.DEGRADED

    def _record_dropped(self) -> None:
        """Mark an event as dropped (retries exhausted)."""
        self._stats["events_dropped"] += 1

    # ── Identity ─────────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        """Human-readable name for this sink type."""
        return self.__class__.__name__


# ─── Null sink (default) ──────────────────────────────────────────────────


class NullSink(AuditSink):
    """No-op sink. Used when no external sink is configured.

    Discards all events silently. Tracks stats for observability
    but does nothing with the data.
    """

    def send(self, event: AuditEvent) -> None:
        """Discard the event. No-op."""
        logger.debug("NullSink: discarding event %s (%s)", event.event_id[:8], event.event_type.value)
        # Don't count null-sink sends as real sends — they're discarded


# ─── Sink registry ────────────────────────────────────────────────────────

SINK_REGISTRY: dict[str, type[AuditSink]] = {}


def register_sink(name: str, cls: type[AuditSink]) -> None:
    """Register a sink class under a name for config-driven instantiation."""
    if name in SINK_REGISTRY:
        logger.warning("Overwriting sink registry entry for '%s'", name)
    SINK_REGISTRY[name] = cls


def create_sink(name: str, config: SinkConfig | None = None, **kwargs: Any) -> AuditSink:
    """Create a sink instance by name from the registry.

    Additional keyword arguments are passed to the sink constructor.
    """
    if name not in SINK_REGISTRY:
        raise ValueError(f"Unknown sink type: '{name}'. Available: {list(SINK_REGISTRY)}")
    return SINK_REGISTRY[name](config, **kwargs)
