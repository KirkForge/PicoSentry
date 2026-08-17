"""Daemon availability — WO4.0.0-002.

Regression tests for: ThreadingHTTPServer, worker pool with real job states
(queued→running→completed), /health staying responsive during a long scan,
signal handling (SIGTERM/SIGINT from a helper thread, SIGHUP rebinding the
RAW socket), the queued webhook sink, and the create_app(tokens=…) fix.
"""

from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from http.server import ThreadingHTTPServer
from unittest.mock import MagicMock, patch

import pytest

import picosentry.sandbox.audit.logger as audit_logger_mod
import picosentry.sandbox.daemon.handler_routes_post as handler_routes_post
from picosentry.sandbox.daemon.server import PicoDomeDaemon, create_app

SUBMITTER_TOKEN = "picodome-submitter-availability-token-000001"


@pytest.fixture(autouse=True)
def reset_audit_singleton():
    original = audit_logger_mod._audit_logger
    yield
    audit_logger_mod._audit_logger = original


@pytest.fixture(autouse=True)
def clean_handler_state():
    """Isolate PicoDomeHandler class attrs each test (daemon init mutates them)."""
    from picosentry.sandbox.daemon.handler import PicoDomeHandler

    saved = (PicoDomeHandler.scan_executor, PicoDomeHandler.scan_slots)
    yield
    PicoDomeHandler.scan_executor, PicoDomeHandler.scan_slots = saved


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _http_request(port: int, method: str, path: str, body: dict | None = None, token: str | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = json.dumps(body) if body is not None else None
    conn.request(method, path, body=payload, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, json.loads(data) if data else {}


def _wait_healthy(port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, _ = _http_request(port, "GET", "/health")
            if status == 200:
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("daemon did not become healthy")


# ─── Threading server ────────────────────────────────────────────────────────


class TestThreadingServer:
    def test_daemon_uses_threading_http_server(self, tmp_path):
        with patch.dict("os.environ", {"PICODOME_JOB_STORE_DIR": str(tmp_path)}):
            daemon = PicoDomeDaemon(host="127.0.0.1", port=_free_port())
            daemon.start(background=True)
            try:
                assert isinstance(daemon._server, ThreadingHTTPServer)
            finally:
                daemon.stop()

    def test_metrics_server_threading(self, tmp_path):
        port = _free_port()
        with patch.dict("os.environ", {"PICODOME_JOB_STORE_DIR": str(tmp_path)}):
            daemon = PicoDomeDaemon(host="127.0.0.1", port=port, metrics_port=_free_port())
            daemon.start(background=True)
            try:
                assert isinstance(daemon._metrics_server, ThreadingHTTPServer)
            finally:
                daemon.stop()


class _FakeScanResult:
    def __init__(self):
        self.overall_verdict = type("V", (), {"value": "ALLOW"})()
        self.exit_code = 0
        self.duration_ms = 1
        self.backend_name = "test"
        self.isolation_level = "test"
        self.enforcement_guarantee = "best-effort"
        self.degraded = False

    def to_dict(self, deterministic=False):
        return {"verdict": "ALLOW"}


class _FakeAnalysisResult:
    def __init__(self):
        self.overall_verdict = type("V", (), {"value": "CLEAN"})()
        self.findings = []

    def to_dict(self, deterministic=False):
        return {"verdict": "CLEAN"}


@pytest.fixture()
def fake_engine(monkeypatch):
    """Replace the l3/l4 execution chain in the POST route with fakes."""
    release = threading.Event()

    def blocking_scan(**kwargs):
        release.wait(timeout=30)
        return _FakeScanResult()

    def fake_analyze(profile, rules=None, deterministic=False):
        return _FakeAnalysisResult()

    monkeypatch.setattr(handler_routes_post, "sandbox_run", blocking_scan)
    monkeypatch.setattr(handler_routes_post, "profile_from_sandbox_result", lambda sr: object())
    monkeypatch.setattr(
        handler_routes_post, "create_default_engine", lambda: type("E", (), {"analyze": staticmethod(fake_analyze)})()
    )
    return release


# ─── Availability under a long scan ──────────────────────────────────────────


class TestHealthDuringLongScan:
    def test_health_responds_fast_while_scan_blocks(self, tmp_path, fake_engine):
        release = fake_engine
        port = _free_port()

        env = {
            "PICODOME_JOB_STORE_DIR": str(tmp_path),
            "PICODOME_API_TOKENS": SUBMITTER_TOKEN,
            "PICODOME_SCAN_WORKERS": "2",
        }
        with patch.dict("os.environ", env):
            daemon = PicoDomeDaemon(host="127.0.0.1", port=port)
            daemon.start(background=True)
        try:
            _wait_healthy(port)

            post_done = threading.Event()
            post_statuses: list[int] = []

            def _post_scan():
                status, _ = _http_request(
                    port,
                    "POST",
                    "/api/v1/scan",
                    body={"command": ["echo", "slow"], "timeout": 20},
                    token=SUBMITTER_TOKEN,
                )
                post_statuses.append(status)
                post_done.set()

            poster = threading.Thread(target=_post_scan, daemon=True)
            poster.start()

            # Wait until the scan is actually running (worker started it).
            from picosentry.sandbox.daemon.handler import PicoDomeHandler

            deadline = time.monotonic() + 5
            job = None
            while time.monotonic() < deadline:
                jobs = PicoDomeHandler.job_store.list_recent(limit=5)
                if jobs:
                    job = jobs[0]
                    if job.get("status") == "running":
                        break
                time.sleep(0.02)
            assert job is not None and job["status"] == "running", f"job never reached running: {job}"

            # /health must answer fast while the scan blocks the worker.
            t0 = time.monotonic()
            status, _ = _http_request(port, "GET", "/health")
            elapsed = time.monotonic() - t0
            assert status == 200
            assert elapsed < 1.0, f"/health took {elapsed:.2f}s while a scan was in flight"

            release.set()
            assert post_done.wait(timeout=10)
            assert post_statuses == [201]

            # Job ends completed.
            jobs = PicoDomeHandler.job_store.list_recent(limit=5)
            assert jobs[0]["status"] == "completed"
        finally:
            release.set()
            daemon.stop()

    def test_queue_full_rejects_with_429(self, tmp_path, fake_engine):
        release = fake_engine
        port = _free_port()

        env = {
            "PICODOME_JOB_STORE_DIR": str(tmp_path),
            "PICODOME_API_TOKENS": SUBMITTER_TOKEN,
            "PICODOME_SCAN_WORKERS": "1",
            "PICODOME_SCAN_QUEUE": "0",
        }
        with patch.dict("os.environ", env):
            daemon = PicoDomeDaemon(host="127.0.0.1", port=port)
            daemon.start(background=True)
        try:
            _wait_healthy(port)
            statuses: list[int] = []

            def _post():
                status, _ = _http_request(
                    port, "POST", "/api/v1/scan", body={"command": ["echo", "x"]}, token=SUBMITTER_TOKEN
                )
                statuses.append(status)

            first = threading.Thread(target=_post, daemon=True)
            first.start()
            # Occupy the single slot.
            from picosentry.sandbox.daemon.handler import PicoDomeHandler

            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                jobs = PicoDomeHandler.job_store.list_recent(limit=5)
                if jobs and jobs[0].get("status") == "running":
                    break
                time.sleep(0.02)

            t0 = time.monotonic()
            status2, body2 = _http_request(
                port, "POST", "/api/v1/scan", body={"command": ["echo", "y"]}, token=SUBMITTER_TOKEN
            )
            assert time.monotonic() - t0 < 5
            assert status2 == 429, body2
            assert "queue full" in body2.get("detail", "") or body2.get("error") == "RATE_LIMITED"

            release.set()
            first.join(timeout=10)
            assert statuses == [201]
        finally:
            release.set()
            daemon.stop()


# ─── Signals ─────────────────────────────────────────────────────────────────


class TestSignalHandling:
    def test_shutdown_handler_is_non_blocking_and_stops_daemon(self, tmp_path):
        import signal

        with patch.dict("os.environ", {"PICODOME_JOB_STORE_DIR": str(tmp_path)}):
            daemon = PicoDomeDaemon(host="127.0.0.1", port=_free_port())
            daemon.start(background=True)
            old_term = signal.getsignal(signal.SIGTERM)
            old_int = signal.getsignal(signal.SIGINT)
            try:
                daemon.install_signal_handlers()
                handler = signal.getsignal(signal.SIGTERM)

                t0 = time.monotonic()
                handler(signal.SIGTERM, None)  # runs on this (non-serve) thread
                assert time.monotonic() - t0 < 1.0, "signal handler blocked"

                deadline = time.monotonic() + 5
                while daemon._server is not None and time.monotonic() < deadline:
                    time.sleep(0.02)
                assert daemon._server is None, "daemon did not stop after SIGTERM handler"
            finally:
                signal.signal(signal.SIGTERM, old_term)
                signal.signal(signal.SIGINT, old_int)
                daemon.stop()

    def test_sighup_rebinds_raw_socket_and_keeps_serving(self, tmp_path, monkeypatch):
        port = _free_port()
        with patch.dict("os.environ", {"PICODOME_JOB_STORE_DIR": str(tmp_path)}):
            daemon = PicoDomeDaemon(host="127.0.0.1", port=port)
            daemon.start(background=True)
        try:
            _wait_healthy(port)
            assert daemon._raw_socket is not None

            wrapped_sockets = []

            class FakeSSLSocket:
                def __init__(self, sock):
                    self._sock = sock
                    self._closed = False

                def fileno(self):
                    return self._sock.fileno()

                def close(self):
                    self._closed = True

            class FakeCtx:
                def wrap_socket(self, sock, server_side=True):
                    wrapped_sockets.append(sock)
                    return FakeSSLSocket(sock)

            import picosentry.sandbox.mtls as mtls_mod

            monkeypatch.setattr(mtls_mod, "reload_ssl_context", lambda config=None: FakeCtx())

            daemon._reload_tls()
            time.sleep(0.3)  # let the serve loop restart

            # The listener was rebound from the RAW socket, not re-wrapping the
            # previous (fake) SSL socket.
            assert daemon._server is not None
            assert isinstance(daemon._server.socket, FakeSSLSocket)
            assert wrapped_sockets, "wrap_socket never called"
            assert not isinstance(wrapped_sockets[0], FakeSSLSocket), "double wrap: SSL socket re-wrapped"

            # Reload back to plaintext — keeps serving HTTP.
            monkeypatch.setattr(mtls_mod, "reload_ssl_context", lambda config=None: None)
            daemon._reload_tls()
            time.sleep(0.3)
            assert not isinstance(daemon._server.socket, FakeSSLSocket)

            status, _ = _http_request(port, "GET", "/health")
            assert status == 200, "listener dead after SIGHUP reloads"
        finally:
            daemon.stop()


# ─── Webhook sink queue ──────────────────────────────────────────────────────


class TestQueuedWebhookSink:
    def _fake_event(self, n):
        event = MagicMock()
        event.event_id = f"evt-{n:04d}"
        event.to_dict.return_value = {"n": n}
        return event

    def test_send_never_blocks_and_drops_counted(self):
        from picosentry.sandbox.daemon.webhook_sink import QueuedWebhookSink

        release = threading.Event()
        inner_started = threading.Event()
        received = []

        class BlockingInner:
            name = "BlockingInner"

            def start(self):
                pass

            def stop(self):
                pass

            def send(self, event):
                inner_started.set()
                release.wait(timeout=10)
                received.append(event.event_id)

        sink = QueuedWebhookSink(BlockingInner(), maxsize=2)
        sink.start()
        try:
            sink.send(self._fake_event(1))
            assert inner_started.wait(timeout=5), "writer never picked up the first event"

            t0 = time.monotonic()
            sink.send(self._fake_event(2))
            sink.send(self._fake_event(3))
            sink.send(self._fake_event(4))  # queue holds 2 → dropped
            assert time.monotonic() - t0 < 1.0, "send() blocked on a stuck webhook"

            assert sink.dropped == 1
            release.set()
            sink.flush(timeout=5)
            assert sorted(received) == ["evt-0001", "evt-0002", "evt-0003"]
            assert sink.stats["queue_dropped"] == 1
        finally:
            release.set()
            sink.stop()

    def test_daemon_wraps_webhook_sink(self, tmp_path, monkeypatch):
        from picosentry.sandbox.audit.sinks.webhook_sink import WebhookSink
        from picosentry.sandbox.daemon.webhook_sink import QueuedWebhookSink

        env = {
            "PICODOME_JOB_STORE_DIR": str(tmp_path),
            "PICODOME_AUDIT_SINKS": "webhook",
            "PICODOME_WEBHOOK_URL": "http://127.0.0.1:1/hook",
        }
        with patch.dict("os.environ", env):
            daemon = PicoDomeDaemon(host="127.0.0.1", port=_free_port())
        webhooks = [s for s in daemon._sinks if isinstance(s, QueuedWebhookSink)]
        assert len(webhooks) == 1
        assert isinstance(webhooks[0]._inner, WebhookSink)
        webhooks[0].stop()
        # No daemon.start() was called: the inner sink's HEAD probe never ran;
        # stopping keeps the (unstarted) writer join cheap and safe.


# ─── create_app(tokens=…) no-op fix ──────────────────────────────────────────


class TestCreateAppTokens:
    def test_tokens_now_reach_tokenauth(self, tmp_path):
        from picosentry.sandbox.daemon.handler import PicoDomeHandler

        with patch.dict("os.environ", {"PICODOME_JOB_STORE_DIR": str(tmp_path)}, clear=False):
            create_app(tokens=SUBMITTER_TOKEN, host="127.0.0.1", port=0)
            assert PicoDomeHandler.auth.validate(SUBMITTER_TOKEN)
            assert PicoDomeHandler.auth.has_permission(SUBMITTER_TOKEN, "scan:submit")
            assert not PicoDomeHandler.auth.validate("picodome-submitter-wrong-token-00000001")
