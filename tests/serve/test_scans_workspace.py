"""``POST /scans`` workspace + role regression suite (P0 fix).

Pins the new contract on the serve-mode scan endpoint:

  1. Viewers are rejected with 403.  Scans are operator+ work.
  2. Operators can scan a target that resolves inside the configured
     ``PICOSHOGUN_SCANS_WORKSPACE_ROOT`` (the test conftest sets this
     to ``/tmp``).
  3. Operators are rejected with 403 if the target resolves OUTSIDE
     that root.  The verdict's main concern was filesystem probing
     through an authenticated viewer — this gate is the fix.
  4. When ``scans_workspace_root`` is unset the endpoint returns 503
     with a clear "configure it" message; it does NOT silently fall
     back to "any path on the server is fair game".

The conftest sets ``PICOSHOGUN_SCANS_WORKSPACE_ROOT=/tmp`` for the
default test env, so the existing 200-happy-path tests in
``test_integration.py`` keep working.  This file is for the rejection
paths and for the 503-when-unset case, which the conftest needs to
opt out of.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from picosentry.serve.api.server import app
from picosentry.serve.config.settings import settings
from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.services.auth import AuthService


@pytest.fixture
def _isolated_auth(tmp_path_factory):
    """Fresh SQLite DB + AuthService for tests that provision users.

    The global ``picoshogun.db`` singleton is shared across the serve suite
    and can be rebound by other module-scoped fixtures under pytest-xdist.
    Giving each user-provisioning test its own DB removes any possibility that
    a create/authenticate round-trip reads stale or swapped state.
    """
    db_path = tmp_path_factory.mktemp("scans_auth") / "auth.db"
    manager = DatabaseManager(db_path=db_path, backend="sqlite")
    auth = AuthService(db=manager)
    yield manager, auth
    manager.close()


@pytest.fixture
def fresh_admin(_isolated_auth) -> dict[str, Any]:
    """Operator account via the service layer.  The registration
    endpoint only creates viewers (P0 fix); elevated roles are
    provisioned here."""
    _, auth = _isolated_auth
    suffix = f"{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
    username = f"scan_admin_{suffix}"
    password = "TestPassword123!"
    user_id = auth.create_user(username, password, role="operator")
    assert user_id is not None
    token = auth.authenticate(username, password)
    assert token is not None
    return {"username": username, "password": password, "token": token, "user_id": user_id}


@pytest.fixture
def fresh_viewer(_isolated_auth) -> dict[str, Any]:
    """Viewer account via the (now viewer-only) registration endpoint."""
    _, auth = _isolated_auth
    suffix = f"{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
    username = f"scan_viewer_{suffix}"
    password = "TestPassword123!"
    user_id = auth.create_user(username, password, role="viewer")
    assert user_id is not None
    token = auth.authenticate(username, password)
    assert token is not None
    return {"username": username, "password": password, "token": token, "user_id": user_id}


def test_viewer_is_rejected_with_403(fresh_viewer: dict[str, Any]) -> None:
    """A viewer token hitting /scans must get 403, not 200.  This is the
    primary P0 fix: the endpoint used to be open to any authenticated
    user."""
    client = TestClient(app)
    resp = client.post(
        "/api/v1/scans",
        json={"target": "/tmp", "rules": None, "format": "json"},
        headers={"Authorization": f"Bearer {fresh_viewer['token']}"},
    )
    assert resp.status_code == 403, f"viewer should be rejected; got {resp.status_code}: {resp.text}"


def test_operator_inside_workspace_returns_200(
    fresh_admin: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """An operator scanning a target inside the configured workspace
    succeeds.  We point the engine at a stub that returns immediately
    so this test runs in milliseconds; the engine itself is exercised
    by the broader scan suite.  What we pin here is the gate, not the
    scan."""
    # Use a small temp workspace.  This is a unit test of the gate, so
    # the workspace contents don't matter — only that the resolver
    # agrees the target is inside the root.
    workspace = tmp_path
    target = tmp_path / "inside_target"
    target.mkdir()
    monkeypatch.setattr(settings.security, "scans_workspace_root", workspace)

    # Stub the engine so we don't actually run a 26s scan.

    target_str = str(target)

    class _StubResult:
        def __init__(self) -> None:
            self.scan_id = "stub-scan"
            self.started_at = "2026-06-12T00:00:00Z"
            self.target = target_str
            self.engine_version = "0.0.0-stub"
            self.findings: list = []
            self.stats = type("S", (), {"to_dict": staticmethod(dict)})()

    class _StubEngine:
        def scan(self, *args, **kwargs):
            return _StubResult()

    # The router imports the symbol directly:
    monkeypatch.setattr(
        "picosentry.serve.api.routers.scans._create_engine",
        lambda *a, **kw: _StubEngine(),
    )

    client = TestClient(app)
    resp = client.post(
        "/api/v1/scans",
        json={"target": str(target), "rules": None, "format": "json"},
        headers={"Authorization": f"Bearer {fresh_admin['token']}"},
    )
    assert resp.status_code == 200, f"operator-inside-workspace should succeed; got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "scan_id" in data


def test_operator_outside_workspace_is_rejected(fresh_admin: dict[str, Any]) -> None:
    """An operator trying to scan a target OUTSIDE the workspace must
    get 403, with a generic "outside workspace" message (no echo of the
    rejected path — the verdict flagged filesystem probing as the main
    risk)."""
    client = TestClient(app)
    # The conftest sets the workspace to /tmp.  /etc/passwd and the
    # caller's home are not under /tmp on any sane Linux box.
    for outside in ("/etc/passwd", "/var/log/syslog", "/root"):
        resp = client.post(
            "/api/v1/scans",
            json={"target": outside, "rules": None, "format": "json"},
            headers={"Authorization": f"Bearer {fresh_admin['token']}"},
        )
        assert resp.status_code == 403, (
            f"target {outside!r} should be rejected (outside /tmp); got {resp.status_code}: {resp.text}"
        )
        # The response should NOT echo the rejected path back to the
        # caller — that's the kind of echo that turns a 403 into a
        # directory listing.
        assert outside not in resp.text


def test_no_workspace_configured_returns_503(fresh_admin: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """When ``scans_workspace_root`` is unset, /scans is disabled and
    returns 503 with a clear "configure it" message.  A fresh deploy
    must NOT silently accept arbitrary paths.

    The conftest sets the env var by default; we clear the dataclass
    attribute (env-var defaults are read at dataclass construction)."""
    # Clear the dataclass value directly.  This is a unit test for the
    # endpoint's behavior, not the env-var resolution path.
    monkeypatch.setattr(settings.security, "scans_workspace_root", None)

    client = TestClient(app)
    resp = client.post(
        "/api/v1/scans",
        json={"target": "/tmp", "rules": None, "format": "json"},
        headers={"Authorization": f"Bearer {fresh_admin['token']}"},
    )
    assert resp.status_code == 503, f"unset workspace should return 503; got {resp.status_code}: {resp.text}"
    assert "SCANS_WORKSPACE_ROOT" in resp.text, "503 response should point operators at the env var to set"


def test_workspace_root_is_resolved_against_symlinks(fresh_admin: dict[str, Any], tmp_path) -> None:
    """``Path.resolve()`` follows symlinks before we check
    ``relative_to``; the path-traversal class of bypass depends on
    this.  Build a symlink that points OUTSIDE the workspace and
    confirm it's still rejected."""
    # /tmp is the configured workspace.  Create a symlink inside /tmp
    # that points to /etc/passwd; the resolved target is outside the
    # workspace even though the user-supplied path is inside it.
    try:
        symlink_path = tmp_path / "etc_passwd_link"
        symlink_path.symlink_to("/etc/passwd")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create symlink on this platform: {exc}")

    client = TestClient(app)
    resp = client.post(
        "/api/v1/scans",
        json={"target": str(symlink_path), "rules": None, "format": "json"},
        headers={"Authorization": f"Bearer {fresh_admin['token']}"},
    )
    assert resp.status_code == 403, f"symlink-resolved target should be rejected; got {resp.status_code}: {resp.text}"
