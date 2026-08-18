"""WO-013: /health must not starve the event loop, and probe persistence is
interval-based (per probe), not per request.

The endpoint is unauthenticated and rate-limit-exempt — an on-loop SMTP probe
(5s timeout) multiplied by anonymous parallel GETs froze every other handler.
"""

from __future__ import annotations

import threading
import time

import pytest
from fastapi.testclient import TestClient

from picosentry.serve.api.server import app
from picosentry.serve.database.manager import db
from picosentry.serve.services import _orchestrator_health as health_mod


class _BlockingSMTP:
    """Stand-in for smtplib.SMTP whose probe blocks until released."""

    release = threading.Event()
    entered = threading.Event()

    def __init__(self, *args, **kwargs):
        self.entered.set()
        assert self.release.wait(10), "SMTP probe was never released"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return True


class TestHealthNeverBlocksLoop:
    def test_handler_not_starved_while_probe_hangs(self, monkeypatch):
        """With the SMTP probe wedged, an unrelated handler must still answer
        immediately — the probe runs in the threadpool, never on the loop."""
        _BlockingSMTP.release = threading.Event()
        _BlockingSMTP.entered = threading.Event()
        monkeypatch.setattr(health_mod.smtplib, "SMTP", _BlockingSMTP)
        monkeypatch.setattr(health_mod.settings.alerts, "email_smtp_host", "smtp.invalid.test")

        result: list = []

        def _hit_health():
            client = TestClient(app)
            result.append(client.get("/health").status_code)
            client.close()

        thread = threading.Thread(target=_hit_health, daemon=True)
        thread.start()
        # Wait until the probe is actually wedged, then time an unrelated
        # handler: the wedged probe must not bleed its 5s timeout onto it.
        assert _BlockingSMTP.entered.wait(5), "/health never reached the SMTP probe"
        start = time.monotonic()
        live = TestClient(app).get("/health/live")
        elapsed = time.monotonic() - start
        assert live.status_code == 200
        assert elapsed < 1.5, f"/health/live blocked {elapsed:.2f}s while the probe hung"

        _BlockingSMTP.release.set()
        thread.join(timeout=10)
        assert result and result[0] == 200


class TestHealthCache:
    def test_burst_hits_single_probe(self, monkeypatch):
        """N rapid /health requests run ONE probe batch (TTL cache)."""
        calls: list[int] = []

        def _fake_probe(registry):
            calls.append(1)
            return [
                {
                    "component": "db",
                    "status": "healthy",
                    "message": "ok",
                    "latency_ms": 0,
                    "timestamp": "2026-08-17T00:00:00+00:00",
                }
            ]

        monkeypatch.setattr(health_mod, "perform_health_checks", _fake_probe)
        client = TestClient(app)
        for _ in range(5):
            resp = client.get("/health")
            assert resp.status_code == 200
            assert resp.json()["overall"] == "healthy"
        assert calls == [1], f"expected exactly one probe, ran {len(calls)}"

    def test_inserts_happen_per_probe_not_per_request(self, monkeypatch):
        """Probe persistence (health_checks rows) follows probe frequency,
        not request frequency — the old code inserted 3-4 rows per GET."""

        def _fake_probe(registry):
            db.execute_insert(
                "INSERT INTO health_checks (component, status, message, latency_ms) VALUES (?, ?, ?, ?)",
                ("probe_marker", "healthy", "ok", 0),
            )
            return []

        monkeypatch.setattr(health_mod, "perform_health_checks", _fake_probe)
        client = TestClient(app)
        for _ in range(4):
            assert client.get("/health").status_code == 200

        rows = db.execute("SELECT COUNT(*) AS c FROM health_checks WHERE component = 'probe_marker'")
        assert rows[0]["c"] == 1, "health probe rows were written per-request instead of per-probe"
        db.execute("DELETE FROM health_checks WHERE component = 'probe_marker'")

    def test_retention_trim_bounds_history(self, monkeypatch):
        """The probe trims health_checks to the retention cap."""
        monkeypatch.setattr(health_mod, "_HEALTH_RETENTION_ROWS", 5)
        for _ in range(8):
            db.execute_insert(
                "INSERT INTO health_checks (component, status, message, latency_ms) VALUES ('old', 'healthy', 'x', 0)"
            )

        health_mod.perform_health_checks({})
        count = db.execute_one("SELECT COUNT(*) AS c FROM health_checks")["c"]
        assert count <= 5, f"retention trim left {count} rows"
        db.execute("DELETE FROM health_checks")


class TestReadyProbeOffLoop:
    """WO5.0.0-020: the /health/ready DB ping must not run on the event loop.

    The endpoint is unauthenticated and limiter-exempt (k8s contract); with
    the ping on the loop, a slow DB wedged every concurrent handler for free.
    """

    @pytest.mark.asyncio
    async def test_live_answers_while_ready_db_ping_wedged(self, monkeypatch):
        import asyncio
        import time

        from httpx import ASGITransport, AsyncClient

        from picosentry.serve.api.server import app
        from picosentry.serve.database import manager as db_mod

        entered = threading.Event()
        release = threading.Event()
        real_execute_one = db_mod.db.execute_one

        def _stall(query, *args, **kwargs):
            entered.set()
            # Safety bound only: on regression the elapsed assertion below
            # fails once this unblocks.
            assert release.wait(10), "ready probe was never released"
            return real_execute_one(query, *args, **kwargs)

        monkeypatch.setattr(db_mod.db, "execute_one", _stall)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            ready = asyncio.create_task(client.get("/health/ready"))
            await asyncio.to_thread(entered.wait, 5)

            start = time.monotonic()
            resp = await asyncio.wait_for(client.get("/health/live"), timeout=2)
            elapsed = time.monotonic() - start
            assert resp.status_code == 200
            assert elapsed < 1.5, f"/health/live blocked {elapsed:.2f}s by the ready probe's DB ping"

            release.set()
            ready_resp = await asyncio.wait_for(ready, timeout=5)
        assert ready_resp.status_code == 200


class TestSmtpHealthPersisted:
    """WO5.0.0-021: the SMTP check must reach the health_checks table.

    It was appended after the persist loop, so health_degraded was
    permanently blind to the one component that times out."""

    def test_unconfigured_smtp_row_persisted_as_disabled(self, monkeypatch):
        monkeypatch.setattr(health_mod.settings.alerts, "email_smtp_host", None)
        health_mod.perform_health_checks({})
        try:
            row = db.execute_one("SELECT status FROM health_checks WHERE component = 'smtp' ORDER BY id DESC LIMIT 1")
            assert row is not None, "smtp check never persisted"
            assert row["status"] == "disabled"
        finally:
            db.execute("DELETE FROM health_checks WHERE component = 'smtp'")

    def test_unreachable_smtp_row_persisted_critical(self, monkeypatch):
        monkeypatch.setattr(health_mod.settings.alerts, "email_smtp_host", "smtp.invalid.test")

        def _boom(*args, **kwargs):
            raise OSError("smtp down")

        monkeypatch.setattr(health_mod.smtplib, "SMTP", _boom)
        health_mod.perform_health_checks({})
        try:
            row = db.execute_one("SELECT status FROM health_checks WHERE component = 'smtp' ORDER BY id DESC LIMIT 1")
            assert row is not None, "smtp check never persisted"
            assert row["status"] == "critical"
        finally:
            db.execute("DELETE FROM health_checks WHERE component = 'smtp'")
