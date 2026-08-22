"""WO7.0.0-002 — HTTP /health must call check_health() and reflect the real
subsystem verdict, matching the gRPC Health() semantics.

HTTP /health used to return {"status": "healthy"} 200 unconditionally — a
dead sandbox kept receiving LB traffic because the load-balancer gate never
went red. This gate proves the HTTP route now calls check_health() and
returns 503 when a subsystem is broken, matching the gRPC Health() verdict
under the same failure.
"""

from __future__ import annotations

import http.client
import socket
import time
from unittest.mock import patch

from picosentry.sandbox.health import HealthStatus


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _http(port: int, path: str):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    import json

    return resp.status, json.loads(data) if data else {}


def _wait_healthy(port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, _ = _http(port, "/health")
            if status == 200:
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("daemon did not become healthy")


class TestHttpHealthCallsCheckHealth:
    """The HTTP /health route must call check_health() and return its verdict."""

    def test_healthy_daemon_returns_200(self, tmp_path, monkeypatch):
        from picosentry.sandbox.daemon.server import PicoDomeDaemon

        def _healthy_check_health():
            return [
                HealthStatus(healthy=True, component="version", detail="1.0", timestamp="now"),
                HealthStatus(healthy=True, component="sandbox_backend", detail="ok", timestamp="now"),
            ]

        monkeypatch.setattr("picosentry.sandbox.health.check_health", _healthy_check_health)

        port = _free_port()
        with patch.dict("os.environ", {"PICODOME_JOB_STORE_DIR": str(tmp_path)}):
            daemon = PicoDomeDaemon(host="127.0.0.1", port=port)
            daemon.start(background=True)
            _wait_healthy(port)
            try:
                status, body = _http(port, "/health")
                assert status == 200
                assert body["status"] == "healthy"
                assert "checks" in body
            finally:
                daemon.stop()

    def test_broken_subsystem_returns_503(self, tmp_path, monkeypatch):
        from picosentry.sandbox.daemon.server import PicoDomeDaemon

        # Inject a failing subsystem: check_health() returns an unhealthy
        # component, mirroring a job_store/audit/store outage.
        def _broken_check_health():
            return [
                HealthStatus(healthy=True, component="version", detail="1.0", timestamp="now"),
                HealthStatus(healthy=False, component="sandbox_backend", detail="error: down", timestamp="now"),
            ]

        monkeypatch.setattr("picosentry.sandbox.health.check_health", _broken_check_health)

        port = _free_port()
        with patch.dict("os.environ", {"PICODOME_JOB_STORE_DIR": str(tmp_path)}):
            daemon = PicoDomeDaemon(host="127.0.0.1", port=port)
            daemon.start(background=True)
            # The daemon may or may not become 200 first; we wait for it to
            # be answering at all, then assert the broken verdict.
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                try:
                    status, _ = _http(port, "/health")
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                raise TimeoutError("daemon did not start answering")
            try:
                status, body = _http(port, "/health")
                assert status == 503, f"expected 503 for broken subsystem, got {status}"
                assert body["status"] == "unhealthy"
                components = {c["component"] for c in body["checks"]}
                assert "sandbox_backend" in components
            finally:
                daemon.stop()

    def test_http_grpc_health_verdict_match(self, tmp_path, monkeypatch):
        """Under the same broken subsystem, HTTP /health and gRPC Health()
        must agree on the verdict (both unhealthy)."""
        from picosentry.sandbox.grpc_transport._servicer import PicoDomeServicer

        def _broken_check_health():
            return [
                HealthStatus(healthy=False, component="sandbox_backend", detail="down", timestamp="now"),
            ]

        monkeypatch.setattr("picosentry.sandbox.health.check_health", _broken_check_health)

        servicer = PicoDomeServicer(scan_engine=None, start_time=time.time(), scan_count_ref=None)
        req = type("Req", (), {})()
        ctx = type("Ctx", (), {})()
        grpc_result = servicer.Health(req, ctx)

        assert grpc_result.healthy is False

        # HTTP path: _handle_health uses the same check_health() under the hood.
        from picosentry.sandbox.daemon.server import PicoDomeDaemon

        port = _free_port()
        with patch.dict("os.environ", {"PICODOME_JOB_STORE_DIR": str(tmp_path)}):
            daemon = PicoDomeDaemon(host="127.0.0.1", port=port)
            daemon.start(background=True)
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                try:
                    _http(port, "/health")
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                raise TimeoutError("daemon did not start answering")
            try:
                status, body = _http(port, "/health")
                assert status == 503
                assert body["status"] == "unhealthy"
                assert grpc_result.healthy is False
            finally:
                daemon.stop()
