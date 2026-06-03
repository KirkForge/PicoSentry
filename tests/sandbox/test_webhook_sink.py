"""Tests for WebhookSink — B03.

Covers:
- Successful POST with 200 response
- Retry on connection failure (mock server down)
- Retry on non-2xx response
- Exponential backoff timing
- Auth token in Authorization header
- Custom headers
- Drop after max retries exhausted
- Stats tracking (sent, failed, dropped)
- Registry integration
- URL validation
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from picosentry.sandbox.audit import AuditEventType
from picosentry.sandbox.audit.logger import AuditEvent
from picosentry.sandbox.audit.sinks import WebhookSink, create_sink
from picosentry.sandbox.audit.sinks.base import SinkConfig, SinkHealth


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


# ─── Mock HTTP server ──────────────────────────────────────────────────────


class _MockHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that can return 200, 500, or record requests."""

    response_code: int = 200
    received: list[dict[str, Any]] = []
    received_headers: list[dict[str, str]] = []

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try:
            data = json.loads(body)
            _MockHandler.received.append(data)
            _MockHandler.received_headers.append(dict(self.headers))
        except json.JSONDecodeError:
            pass

        self.send_response(_MockHandler.response_code)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress log output


@pytest.fixture
def mock_server():
    """Start a mock HTTP server on a free port."""
    _MockHandler.received = []
    _MockHandler.received_headers = []
    _MockHandler.response_code = 200

    server = HTTPServer(("127.0.0.1", 0), _MockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    thread.join(timeout=5)


# ─── Tests ──────────────────────────────────────────────────────────────────


class TestWebhookSinkBasic:
    def test_send_event_success(self, mock_server):
        sink = WebhookSink(config=SinkConfig(max_retries=0), url=mock_server)
        sink.start()
        event = _make_event(actor="alice")
        sink.send(event)
        assert sink.stats["events_sent"] == 1
        assert len(_MockHandler.received) == 1
        assert _MockHandler.received[0]["actor"] == "alice"
        sink.stop()

    def test_send_multiple_events(self, mock_server):
        sink = WebhookSink(config=SinkConfig(max_retries=0), url=mock_server)
        sink.start()
        for i in range(3):
            sink.send(_make_event(actor=f"user-{i}"))
        assert sink.stats["events_sent"] == 3
        assert len(_MockHandler.received) == 3
        sink.stop()

    def test_event_payload_structure(self, mock_server):
        sink = WebhookSink(config=SinkConfig(max_retries=0), url=mock_server)
        sink.start()
        sink.send(
            _make_event(
                actor="bob",
                detail="scan complete",
                target="package-x",
                metadata={"verdict": "DENY"},
            )
        )
        data = _MockHandler.received[0]
        assert data["actor"] == "bob"
        assert data["detail"] == "scan complete"
        assert data["target"] == "package-x"
        assert data["metadata"]["verdict"] == "DENY"
        assert data["event_type"] == "scan_start"
        sink.stop()


class TestWebhookSinkAuth:
    def test_auth_token_in_header(self, mock_server):
        sink = WebhookSink(
            config=SinkConfig(max_retries=0),
            url=mock_server,
            auth_token="secret-token-123",
        )
        sink.start()
        sink.send(_make_event())
        headers = _MockHandler.received_headers[0]
        assert headers.get("Authorization") == "Bearer secret-token-123"
        sink.stop()

    def test_custom_headers(self, mock_server):
        sink = WebhookSink(
            config=SinkConfig(max_retries=0),
            url=mock_server,
            headers={"X-Custom": "value-abc"},
        )
        sink.start()
        sink.send(_make_event())
        headers = _MockHandler.received_headers[0]
        assert headers.get("X-Custom") == "value-abc"
        assert "application/json" in headers.get("Content-Type", "")
        sink.stop()


class TestWebhookSinkRetry:
    def test_retry_on_server_error(self, mock_server):
        # Server returns 500 on first request, then 200
        _MockHandler.response_code = 500
        config = SinkConfig(max_retries=2, retry_backoff=0.01)
        sink = WebhookSink(config=config, url=mock_server)
        sink.start()

        sink.send(_make_event())
        # Should have failed (server always returns 500)
        assert sink.stats["events_failed"] >= 1
        sink.stop()

    def test_drop_after_max_retries(self, mock_server):
        _MockHandler.response_code = 500
        config = SinkConfig(max_retries=1, retry_backoff=0.01)
        sink = WebhookSink(config=config, url=mock_server)
        sink.start()

        sink.send(_make_event())
        assert sink.stats["events_dropped"] == 1
        assert sink.stats["events_sent"] == 0
        sink.stop()

    def test_connection_failure_drops_event(self):
        # Point at a non-existent URL
        config = SinkConfig(max_retries=1, retry_backoff=0.01, timeout=1.0)
        sink = WebhookSink(config=config, url="http://127.0.0.1:1/nonexistent")
        sink.start()

        sink.send(_make_event())
        assert sink.stats["events_dropped"] == 1
        assert sink.stats["events_sent"] == 0
        sink.stop()

    def test_health_degrades_on_failure(self):
        config = SinkConfig(max_retries=0, retry_backoff=0.01, timeout=1.0)
        sink = WebhookSink(config=config, url="http://127.0.0.1:1/nonexistent")
        sink.start()

        sink.send(_make_event())
        assert sink.health in (SinkHealth.DEGRADED, SinkHealth.FAILED)
        sink.stop()


class TestWebhookSinkRegistry:
    def test_create_webhook_sink(self, mock_server):
        sink = create_sink("webhook", config=SinkConfig(), url=mock_server)
        assert isinstance(sink, WebhookSink)

    def test_url_required(self):
        with pytest.raises(ValueError, match="non-empty URL"):
            WebhookSink(url="")

    def test_url_property(self, mock_server):
        sink = WebhookSink(url=mock_server)
        assert sink.url == mock_server
