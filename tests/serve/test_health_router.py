"""``/health/ready`` exception-narrowing regression suite.

Pins the contract that the readiness probe only catches expected DB
failure modes and returns a sanitized 503; unexpected / control-flow
exceptions are left for the global exception handler.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from picosentry.serve.api.server import app
from picosentry.serve.database.manager import db


def test_ready_db_failure_returns_503(monkeypatch: pytest.MonkeyPatch) -> None:
    """An OSError/ValueError/RuntimeError from the DB probe is caught and
    surfaced as a 503 'not ready' without crashing the route."""

    def _failing_execute_one(*_a, **_kw) -> None:
        raise OSError("database is down")

    monkeypatch.setattr(db, "execute_one", _failing_execute_one)

    client = TestClient(app)
    resp = client.get("/health/ready")
    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "not ready"
    assert data["checks"]["database"] == "unavailable"


def test_ready_unexpected_error_returns_generic_500(monkeypatch: pytest.MonkeyPatch) -> None:
    """A programmer error in the DB probe is NOT swallowed by the route's
    catch tuple; the global handler turns it into a generic 500 so bugs
    cannot be masked as 'not ready'."""

    def _buggy_execute_one(*_a, **_kw) -> None:
        raise NameError("programmer bug")

    monkeypatch.setattr(db, "execute_one", _buggy_execute_one)

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/health/ready")
    assert resp.status_code == 500
    assert "database unavailable" not in resp.text


def test_status_threat_score_is_intelligence_aggregate(monkeypatch: pytest.MonkeyPatch) -> None:
    """/status must surface the intelligence threat score, not an average of
    health-probe latencies (WO-012: 'slow DB ping' is not 'under attack')."""
    import asyncio

    from picosentry.serve.api.routers import health as health_router
    from picosentry.serve.services.orchestrator import orchestrator

    monkeypatch.setattr(
        orchestrator,
        "get_status",
        lambda org_id=None: {
            "projects_total": 1,
            "projects_active": 0,
            "projects_failed": 0,
            "active_threats": 3,
            "pending_alerts": 0,
            "threat_score": 42.5,
            "system_health": "healthy",
            "uptime_seconds": 10.0,
        },
    )

    status = asyncio.run(health_router.get_status(user={"id": 1}, org={"id": 1}))
    assert status.threat_score == 42.5
