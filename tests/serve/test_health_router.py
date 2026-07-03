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
    assert data["detail"] == "database unavailable"


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
