"""``POST /sandboxes`` exception-narrowing regression suite.

Pins the contract that the sandbox execution endpoint only catches
expected, operational failures from the L3 engine and surfaces them as
a sanitized 500.  Unexpected / control-flow exceptions must not be
swallowed.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from picosentry.serve.api.server import app
from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.services.auth import AuthService


@pytest.fixture
def _isolated_auth(tmp_path_factory):
    """Fresh SQLite DB + AuthService for tests that provision users.

    Mirrors the isolation in ``tests/serve/test_scans_workspace.py`` so
    the sandbox router auth fixtures cannot be affected by the shared
    global DB singleton under pytest-xdist.
    """
    db_path = tmp_path_factory.mktemp("sandbox_auth") / "auth.db"
    manager = DatabaseManager(db_path=db_path, backend="sqlite")
    auth = AuthService(db=manager)
    yield manager, auth
    manager.close()


@pytest.fixture
def fresh_operator(_isolated_auth) -> dict[str, Any]:
    _, auth = _isolated_auth
    suffix = f"{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
    username = f"sandbox_op_{suffix}"
    password = "TestPassword123!"
    user_id = auth.create_user(username, password, role="operator")
    assert user_id is not None
    token = auth.authenticate(username, password)
    assert token is not None
    return {"username": username, "password": password, "token": token, "user_id": user_id}


def test_sandbox_runtime_error_returns_500(fresh_operator: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """A RuntimeError from the L3 engine (e.g. backend unavailable) is
    caught and returned as a sanitized 500."""

    def _failing_sandbox_run(*_a, **_kw):
        raise RuntimeError("backend failed")

    monkeypatch.setattr(
        "picosentry.serve.api.routers.scans._sandbox_run",
        _failing_sandbox_run,
    )

    client = TestClient(app)
    resp = client.post(
        "/api/v1/sandboxes",
        json={"command": ["true"], "timeout": 10},
        headers={"Authorization": f"Bearer {fresh_operator['token']}"},
    )
    assert resp.status_code == 500
    assert "Sandbox execution failed" in resp.text


def test_sandbox_unexpected_error_returns_generic_500(
    fresh_operator: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A programmer error (e.g. NameError) is NOT swallowed by the route's
    catch tuple; the global handler turns it into a generic 500 so bugs
    cannot be masked as 'Sandbox execution failed'."""

    def _buggy_sandbox_run(*_a, **_kw):
        raise NameError("programmer bug")

    monkeypatch.setattr(
        "picosentry.serve.api.routers.scans._sandbox_run",
        _buggy_sandbox_run,
    )

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.post(
        "/api/v1/sandboxes",
        json={"command": ["true"], "timeout": 10},
        headers={"Authorization": f"Bearer {fresh_operator['token']}"},
    )
    assert resp.status_code == 500
    assert "Sandbox execution failed" not in resp.text
