"""Tests for audit sink base classes — B01.

Covers:
- SinkConfig immutability and defaults
- NullSink send (no-op, no crash)
- AuditSink lifecycle (start/stop/flush)
- AuditSink stats tracking
- AuditSink health degradation
- Sink registry (register, create, unknown)
- AuditLogger.add_sink / remove_sink forwarding
- Sink failure isolation (sink raises → logger still works)
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from picosentry.sandbox.audit import AuditEventType, AuditLogger
from picosentry.sandbox.audit.logger import AuditEvent
from picosentry.sandbox.audit.sinks.base import (
    SINK_REGISTRY,
    AuditSink,
    NullSink,
    SinkConfig,
    SinkHealth,
    create_sink,
    register_sink,
)

# ─── SinkConfig ─────────────────────────────────────────────────────────────


class TestSinkConfig:
    def test_defaults(self):
        cfg = SinkConfig()
        assert cfg.enabled is True
        assert cfg.batch_size == 1
        assert cfg.flush_interval == 0.0
        assert cfg.max_retries == 3
        assert cfg.retry_backoff == 1.0
        assert cfg.timeout == 10.0

    def test_custom_values(self):
        cfg = SinkConfig(enabled=False, batch_size=50, flush_interval=5.0, max_retries=5)
        assert cfg.enabled is False
        assert cfg.batch_size == 50
        assert cfg.flush_interval == 5.0
        assert cfg.max_retries == 5

    def test_frozen(self):
        cfg = SinkConfig()
        with pytest.raises(FrozenInstanceError):
            cfg.enabled = False

    def test_equality(self):
        a = SinkConfig()
        b = SinkConfig()
        assert a == b

    def test_inequality(self):
        a = SinkConfig(enabled=True)
        b = SinkConfig(enabled=False)
        assert a != b


# ─── NullSink ──────────────────────────────────────────────────────────────


class TestNullSink:
    def test_send_does_not_crash(self):
        sink = NullSink()
        event = AuditEvent(
            event_type=AuditEventType.SCAN_START,
            actor="test",
            event_id="abc123",
            timestamp="2026-01-01T00:00:00Z",
        )
        sink.send(event)  # should not raise

    def test_name(self):
        sink = NullSink()
        assert sink.name == "NullSink"

    def test_stats_initial(self):
        sink = NullSink()
        stats = sink.stats
        assert stats["events_sent"] == 0
        assert stats["events_failed"] == 0
        assert stats["events_dropped"] == 0

    def test_health_initial(self):
        sink = NullSink()
        assert sink.health == SinkHealth.HEALTHY

    def test_start_stop_noop(self):
        sink = NullSink()
        sink.start()  # should not raise
        sink.stop()  # should not raise

    def test_flush_noop(self):
        sink = NullSink()
        sink.flush()  # should not raise


# ─── AuditSink base ─────────────────────────────────────────────────────────


class TestAuditSinkBase:
    def test_record_success(self):
        sink = NullSink()
        sink._record_success()
        assert sink.stats["events_sent"] == 1
        assert sink.stats["last_send_time"] is not None

    def test_record_failure_degrades_health(self):
        sink = NullSink()
        assert sink.health == SinkHealth.HEALTHY
        sink._record_failure("connection refused")
        assert sink.health == SinkHealth.DEGRADED
        assert sink.stats["events_failed"] == 1
        assert sink.stats["last_error"] == "connection refused"

    def test_record_failure_eventual_dead(self):
        sink = NullSink()
        for i in range(6):
            sink._record_failure(f"error {i}")
        assert sink.health == SinkHealth.FAILED

    def test_record_dropped(self):
        sink = NullSink()
        sink._record_dropped()
        assert sink.stats["events_dropped"] == 1

    def test_recovery_from_degraded(self):
        sink = NullSink()
        sink._record_failure("first error")
        assert sink.health == SinkHealth.DEGRADED
        sink._record_success()
        assert sink.health == SinkHealth.HEALTHY

    def test_no_recovery_from_failed(self):
        sink = NullSink()
        for _ in range(6):
            sink._record_failure("error")
        assert sink.health == SinkHealth.FAILED
        sink._record_success()
        # Still FAILED because >5 failures
        assert sink.health == SinkHealth.FAILED

    def test_start_sets_started_at(self):
        sink = NullSink()
        sink.start()
        assert sink.stats["started_at"] is not None

    def test_stats_returns_copy(self):
        sink = NullSink()
        stats1 = sink.stats
        stats2 = sink.stats
        assert stats1 == stats2
        assert stats1 is not stats2  # different objects


# ─── Custom sink subclass ──────────────────────────────────────────────────


class CountingSink(AuditSink):
    """Test sink that counts events it receives."""

    def __init__(self, config: SinkConfig | None = None) -> None:
        super().__init__(config)
        self.received: list[AuditEvent] = []

    def send(self, event: AuditEvent) -> None:
        self.received.append(event)
        self._record_success()


class FailingSink(AuditSink):
    """Test sink that always raises."""

    def send(self, event: AuditEvent) -> None:
        self._record_failure("intentional failure")
        raise RuntimeError("sink broken")


class TestCustomSink:
    def test_counting_sink_receives_events(self):
        sink = CountingSink()
        event = AuditEvent(
            event_type=AuditEventType.SCAN_START,
            actor="test",
            event_id="evt1",
            timestamp="2026-01-01T00:00:00Z",
        )
        sink.send(event)
        assert len(sink.received) == 1
        assert sink.received[0].event_type == AuditEventType.SCAN_START
        assert sink.stats["events_sent"] == 1

    def test_failing_sink_records_failure(self):
        sink = FailingSink()
        event = AuditEvent(
            event_type=AuditEventType.SCAN_START,
            actor="test",
            event_id="evt2",
            timestamp="2026-01-01T00:00:00Z",
        )
        with pytest.raises(RuntimeError):
            sink.send(event)
        assert sink.stats["events_failed"] == 1


# ─── Sink registry ─────────────────────────────────────────────────────────


class TestSinkRegistry:
    def test_null_sink_registered(self):
        assert "null" in SINK_REGISTRY
        assert SINK_REGISTRY["null"] is NullSink

    def test_create_null_sink(self):
        sink = create_sink("null")
        assert isinstance(sink, NullSink)

    def test_create_with_config(self):
        cfg = SinkConfig(timeout=30.0)
        sink = create_sink("null", config=cfg)
        assert isinstance(sink, NullSink)
        assert sink._config.timeout == 30.0

    def test_create_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown sink type"):
            create_sink("nonexistent")

    def test_register_custom_sink(self):
        register_sink("counting", CountingSink)
        assert "counting" in SINK_REGISTRY
        sink = create_sink("counting")
        assert isinstance(sink, CountingSink)
        # Cleanup
        del SINK_REGISTRY["counting"]

    def test_register_overwrites_with_warning(self, caplog):
        register_sink("null", NullSink)
        # Should not raise, just warn
        assert "null" in SINK_REGISTRY


# ─── AuditLogger sink integration ──────────────────────────────────────────


class TestAuditLoggerSinks:
    def test_add_sink_forwards_events(self, tmp_path):
        logger = AuditLogger(log_dir=tmp_path)
        counting = CountingSink()
        logger.add_sink(counting)

        logger.record(
            event_type=AuditEventType.SCAN_START,
            actor="test-user",
            detail="test scan",
        )

        assert len(counting.received) == 1
        assert counting.received[0].actor == "test-user"

    def test_multiple_sinks(self, tmp_path):
        logger = AuditLogger(log_dir=tmp_path)
        sink1 = CountingSink()
        sink2 = CountingSink()
        logger.add_sink(sink1)
        logger.add_sink(sink2)

        logger.record(
            event_type=AuditEventType.SCAN_COMPLETE,
            actor="test-user",
        )

        assert len(sink1.received) == 1
        assert len(sink2.received) == 1

    def test_sink_failure_does_not_crash_logger(self, tmp_path):
        logger = AuditLogger(log_dir=tmp_path)
        failing = FailingSink()
        logger.add_sink(failing)

        # This should NOT raise despite the sink failing
        event = logger.record(
            event_type=AuditEventType.SCAN_ALERT,
            actor="test-user",
        )
        assert event.event_type == AuditEventType.SCAN_ALERT

    def test_remove_sink(self, tmp_path):
        logger = AuditLogger(log_dir=tmp_path)
        counting = CountingSink()
        logger.add_sink(counting)
        logger.remove_sink(counting)

        logger.record(
            event_type=AuditEventType.SCAN_START,
            actor="test-user",
        )

        # Sink was removed, should not receive events
        assert len(counting.received) == 0

    def test_setup_audit_logger_starts_sinks(self, tmp_path):
        from picosentry.sandbox.audit import setup_audit_logger

        counting = CountingSink()
        audit = setup_audit_logger(
            log_dir=tmp_path,
            sinks=[counting],
        )

        assert counting.stats["started_at"] is not None

        # Record an event
        audit.record(
            event_type=AuditEventType.DAEMON_START,
            actor="system",
        )
        assert len(counting.received) == 1

    def test_null_sink_in_logger_does_nothing(self, tmp_path):
        logger = AuditLogger(log_dir=tmp_path)
        null = NullSink()
        logger.add_sink(null)

        # Should not crash, null sink just discards
        logger.record(
            event_type=AuditEventType.SCAN_START,
            actor="test",
        )
