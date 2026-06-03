"""Tests for SyslogSink — B04.

Covers:
- RFC 5424 message formatting
- UDP send success
- Socket not initialized (send before start)
- Event type → severity mapping
- Custom host/port/app_name
- Registry integration
- Lifecycle (start creates socket, stop closes it)
"""

from __future__ import annotations

import socket
import threading

import pytest

from picosentry.sandbox.audit import AuditEventType
from picosentry.sandbox.audit.logger import AuditEvent
from picosentry.sandbox.audit.sinks import SyslogSink, create_sink
from picosentry.sandbox.audit.sinks.base import SinkConfig


def _make_event(actor: str = "test", **kwargs) -> AuditEvent:
    return AuditEvent(
        event_type=kwargs.get("event_type", AuditEventType.SCAN_START),
        actor=actor,
        detail=kwargs.get("detail", ""),
        target=kwargs.get("target", ""),
        metadata=kwargs.get("metadata", {}),
        event_id=kwargs.get("event_id", "evt-001"),
        timestamp=kwargs.get("timestamp", "2026-01-01T00:00:00Z"),
        prev_hash=kwargs.get("prev_hash", ""),
    )


class _UDPCollector:
    """Simple UDP server that collects messages for testing."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((host, port))
        self._sock.settimeout(2.0)
        self.host = host
        self.port = self._sock.getsockname()[1]
        self.messages: list[bytes] = []
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._thread.start()

    def _recv_loop(self):
        while self._running:
            try:
                data, _ = self._sock.recvfrom(8192)
                self.messages.append(data)
            except TimeoutError:
                continue
            except OSError:
                break

    def stop(self):
        self._running = False
        self._sock.close()
        if self._thread:
            self._thread.join(timeout=3)


@pytest.fixture
def udp_collector():
    """Start a UDP collector on a random port."""
    collector = _UDPCollector()
    collector.start()
    yield collector
    collector.stop()


class TestSyslogSinkFormat:
    def test_basic_message_format(self):
        sink = SyslogSink(host="127.0.0.1", port=514)
        event = _make_event(actor="alice", detail="scan started")
        msg = sink._format_message(event)
        # RFC 5424: <pri>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
        assert msg.startswith("<")
        assert ">1 " in msg
        assert "picodome" in msg
        assert "alice" in msg
        assert "scan_start" in msg

    def test_severity_mapping_alert(self):
        sink = SyslogSink()
        event = _make_event(event_type=AuditEventType.SCAN_ALERT)
        msg = sink._format_message(event)
        # SCAN_ALERT should map to warning priority (12)
        assert msg.startswith("<12>")

    def test_severity_mapping_auth_failure(self):
        sink = SyslogSink()
        event = _make_event(event_type=AuditEventType.AUTH_FAILURE)
        msg = sink._format_message(event)
        # AUTH_FAILURE should map to error priority (11)
        assert msg.startswith("<11>")

    def test_severity_mapping_scan_start(self):
        sink = SyslogSink()
        event = _make_event(event_type=AuditEventType.SCAN_START)
        msg = sink._format_message(event)
        # SCAN_START should map to info priority (14)
        assert msg.startswith("<14>")

    def test_message_contains_structured_data(self):
        sink = SyslogSink()
        event = _make_event(
            actor="bob",
            detail="completed",
            target="pkg-x",
            metadata={"verdict": "DENY"},
        )
        msg = sink._format_message(event)
        assert 'actor="bob"' in msg
        assert 'detail="completed"' in msg
        assert 'target="pkg-x"' in msg
        assert 'verdict="DENY"' in msg

    def test_custom_app_name(self):
        sink = SyslogSink(app_name="myapp")
        event = _make_event()
        msg = sink._format_message(event)
        assert "myapp" in msg


class TestSyslogSinkSend:
    def test_send_via_udp(self, udp_collector):
        sink = SyslogSink(
            config=SinkConfig(max_retries=0),
            host=udp_collector.host,
            port=udp_collector.port,
        )
        sink.start()
        sink.send(_make_event(actor="alice"))
        sink.stop()

        assert sink.stats["events_sent"] == 1
        # Wait a moment for UDP delivery
        import time

        time.sleep(0.1)
        assert len(udp_collector.messages) >= 1
        msg = udp_collector.messages[0].decode("utf-8")
        assert "alice" in msg

    def test_send_multiple_events(self, udp_collector):
        sink = SyslogSink(
            config=SinkConfig(max_retries=0),
            host=udp_collector.host,
            port=udp_collector.port,
        )
        sink.start()
        for i in range(5):
            sink.send(_make_event(actor=f"user-{i}"))
        sink.stop()

        assert sink.stats["events_sent"] == 5


class TestSyslogSinkLifecycle:
    def test_start_creates_socket(self):
        sink = SyslogSink(host="127.0.0.1", port=1514)
        assert sink._sock is None
        sink.start()
        assert sink._sock is not None
        sink.stop()
        assert sink._sock is None

    def test_stop_closes_socket(self):
        sink = SyslogSink(host="127.0.0.1", port=1514)
        sink.start()
        sock = sink._sock
        sink.stop()
        assert sink._sock is None
        # Socket should be closed
        with pytest.raises(OSError):
            sock.sendto(b"test", ("127.0.0.1", 1514))

    def test_send_without_start_drops(self):
        sink = SyslogSink(host="127.0.0.1", port=514)
        # Don't call start — socket is None
        sink.send(_make_event())
        assert sink.stats["events_dropped"] == 1
        assert sink.stats["events_failed"] >= 1


class TestSyslogSinkRegistry:
    def test_create_syslog_sink(self):
        sink = create_sink("syslog", host="10.0.0.1", port=514)
        assert isinstance(sink, SyslogSink)

    def test_default_host_port(self):
        sink = SyslogSink()
        assert sink.host == "127.0.0.1"
        assert sink.port == 514

    def test_custom_host_port(self):
        sink = SyslogSink(host="syslog.example.com", port=1514)
        assert sink.host == "syslog.example.com"
        assert sink.port == 1514
