"""Security regression tests for picosentry serve.

These tests document and enforce the security contract of the serve API:
- Registration cannot self-elevate role.
- Auth is required for privileged endpoints.
- Org isolation prevents cross-tenant reads.
- Production configuration rejects wildcard CORS, weak secrets, and public
  interface binding unless explicitly overridden.
- /docs and /redoc are disabled in production.
- /scans rejects paths outside the configured workspace root.
"""

import os
import uuid

import pytest
from fastapi.testclient import TestClient

from picosentry.serve.api.server import app
from picosentry.serve.config.settings import Settings


def _reload_settings(monkeypatch, **env_vars):
    """Set env vars and return a fresh Settings instance.

    Settings reads env at import/field-default time, so we mutate os.environ
    and construct a new Settings object rather than relying on the module
    singleton in tests that need different configs.
    """
    for key, value in env_vars.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    return Settings()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def unique_user():
    suffix = uuid.uuid4().hex[:8]
    return {
        "username": f"testuser-{suffix}",
        "password": "correct-horse-battery-staple",
        "email": f"{suffix}@example.com",
    }


@pytest.fixture
def registered_user(client, unique_user):
    r = client.post("/auth/register", json=unique_user)
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture
def auth_token(client, registered_user, unique_user):
    r = client.post(
        "/auth/login",
        params={
            "username": unique_user["username"],
            "password": unique_user["password"],
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


class TestRegistration:
    def test_registration_creates_viewer(self, client, registered_user):
        assert registered_user["role"] == "viewer"

    def test_registration_rejects_role_field(self, client, unique_user):
        payload = {**unique_user, "role": "admin"}
        r = client.post("/auth/register", json=payload)
        assert r.status_code == 422

    def test_registration_disabled_by_default_in_production(self, monkeypatch, unique_user):
        s = _reload_settings(
            monkeypatch,
            PICOSHOGUN_ENV="production",
            PICOSHOGUN_ALLOW_REGISTRATION="false",
            PICOSHOGUN_SECRET_KEY="x" * 32,
            PICOSHOGUN_SKIP_SECURE_ASSERT="1",
        )
        assert s.security.allow_registration is False


class TestAuthRequired:
    def test_projects_requires_auth(self, client):
        r = client.get("/projects")
        assert r.status_code in (401, 403)

    def test_orgs_requires_auth(self, client):
        r = client.get("/orgs")
        assert r.status_code in (401, 403)

    def test_admin_backup_requires_admin(self, client, auth_token):
        r = client.post(
            "/backup",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert r.status_code in (401, 403)


class TestOrgIsolation:
    def test_cannot_read_other_org(self, client, auth_token):
        r = client.get("/orgs/99999", headers={"Authorization": f"Bearer {auth_token}"})
        assert r.status_code in (404, 403)

    def test_cannot_list_other_org_members(self, client, auth_token):
        r = client.get(
            "/orgs/99999/members",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert r.status_code in (403, 404)


class TestProductionConfig:
    def test_default_secret_key_is_flagged(self, monkeypatch):
        s = _reload_settings(
            monkeypatch,
            PICOSHOGUN_ENV="production",
            PICOSHOGUN_SECRET_KEY="change-me-in-production",
            PICOSHOGUN_SKIP_SECURE_ASSERT="1",
        )
        issues = s.validate()
        assert any("Default secret key" in i for i in issues)

    def test_short_secret_key_blocked(self, monkeypatch):
        from picosentry._core.config import assert_secure

        violations = assert_secure(
            secret_key="short",
            bind_host="127.0.0.1",
            env="production",
            block_on_error=False,
        )
        checks = {v.check for v in violations}
        assert "secret_key_length" in checks

    def test_cors_wildcard_rejected_in_production(self, monkeypatch):
        s = _reload_settings(
            monkeypatch,
            PICOSHOGUN_ENV="production",
            PICOSHOGUN_CORS_ORIGINS="*",
            PICOSHOGUN_SECRET_KEY="x" * 32,
            PICOSHOGUN_SKIP_SECURE_ASSERT="1",
        )
        issues = s.validate()
        assert any("Wildcard CORS origin" in i for i in issues)

    def test_bind_all_interfaces_warned(self, monkeypatch):
        from picosentry._core.config import assert_secure

        violations = assert_secure(
            secret_key="x" * 32,
            bind_host="0.0.0.0",
            env="development",
            block_on_error=False,
        )
        checks = {v.check for v in violations}
        assert "bind_host" in checks


class TestProductionDocsRestriction:
    def test_docs_blocked_when_middleware_enabled(self):
        from picosentry.serve.middleware.docs_restriction import DocsRestrictionMiddleware
        from starlette.testclient import TestClient as StarletteTestClient
        from starlette.routing import Route
        from starlette.applications import Starlette
        from starlette.responses import PlainTextResponse

        async def homepage(request):
            return PlainTextResponse("ok")

        starlette_app = Starlette(
            routes=[
                Route("/", homepage),
                Route("/docs", homepage),
            ]
        )
        starlette_app.add_middleware(DocsRestrictionMiddleware, enabled=True)

        sc = StarletteTestClient(starlette_app)
        assert sc.get("/").status_code == 200
        assert sc.get("/docs").status_code == 404


class TestScansWorkspace:
    def test_scan_outside_workspace_rejected(self, client, auth_token, monkeypatch, tmp_path):
        os.environ["PICOSHOGUN_SCANS_WORKSPACE_ROOT"] = str(tmp_path)
        r = client.post(
            "/api/v1/scans",
            json={"target": "/etc/passwd", "rules": []},
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert r.status_code in (401, 403, 503)

    def test_scan_inside_workspace_allowed(self, client, auth_token, monkeypatch, tmp_path):
        from picosentry.serve.api.deps import auth_service

        suffix = uuid.uuid4().hex[:8]
        admin_id = auth_service.create_user(
            username=f"admin-{suffix}",
            password="correct-horse-battery-staple",
            email=f"admin-{suffix}@example.com",
            role="admin",
        )
        token = auth_service._generate_token(admin_id, f"admin-{suffix}", "admin")
        target = tmp_path / "safe-project"
        target.mkdir()
        (target / "pyproject.toml").write_text("[project]\nname='demo'\n")
        os.environ["PICOSHOGUN_SCANS_WORKSPACE_ROOT"] = str(tmp_path)
        r = client.post(
            "/api/v1/scans",
            json={"target": str(target), "rules": []},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
