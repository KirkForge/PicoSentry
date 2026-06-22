"""Tests for PicoDome daemon surface-area hardening."""

from __future__ import annotations

import sys
import time
from collections.abc import Generator
from pathlib import Path
from urllib.request import urlopen

import pytest

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture
def daemon_port() -> int:
    """Find an ephemeral port for a daemon test instance."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def running_daemon(daemon_port: int) -> Generator[str, None, None]:
    """Start a PicoDome daemon on an ephemeral port and yield its base URL."""
    from picosentry.sandbox.daemon import PicoDomeDaemon

    daemon = PicoDomeDaemon(host="127.0.0.1", port=daemon_port, store_backend="jsonl")
    daemon.start(background=True)
    try:
        # Wait for the server to be ready.
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                urlopen(f"http://127.0.0.1:{daemon_port}/health", timeout=0.5)
                break
            except Exception:
                time.sleep(0.1)
        yield f"http://127.0.0.1:{daemon_port}"
    finally:
        daemon.stop()


class TestDaemonHealthExemption:
    def test_health_not_rate_limited(self, running_daemon: str) -> None:
        """Hammer /health and ensure it never returns 429."""
        for _ in range(50):
            resp = urlopen(f"{running_daemon}/health", timeout=5)
            assert resp.status == 200

    def test_ready_not_rate_limited(self, running_daemon: str) -> None:
        for _ in range(50):
            resp = urlopen(f"{running_daemon}/ready", timeout=5)
            # /ready may return 200 or an enterprise/degraded response.
            assert resp.status != 429


class TestDaemonSecurityHeaders:
    def test_response_has_security_headers(self, running_daemon: str) -> None:
        resp = urlopen(f"{running_daemon}/health", timeout=5)
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert resp.headers.get("Cache-Control") == "no-store"


class TestDaemonInputCaps:
    def test_list_limit_is_capped(self, daemon_port: int) -> None:
        from picosentry.sandbox.daemon.handler_routes_get import _clamped_limit

        query = {"limit": ["999999"]}
        assert _clamped_limit(query, "limit", 50) <= 1000

    def test_audit_limit_is_capped(self, daemon_port: int) -> None:
        from picosentry.sandbox.daemon.handler_routes_get import _clamped_limit

        query = {"limit": ["999999"]}
        assert _clamped_limit(query, "limit", 100) <= 1000

    def test_scan_timeout_is_capped(self) -> None:
        from picosentry.sandbox.daemon.handler_routes_post import _max_scan_timeout_seconds

        assert _max_scan_timeout_seconds() <= 300

    def test_scan_timeout_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from picosentry.sandbox.daemon.handler_routes_post import _max_scan_timeout_seconds

        monkeypatch.setenv("PICODOME_MAX_SCAN_TIMEOUT", "60")
        assert _max_scan_timeout_seconds() == 60.0
