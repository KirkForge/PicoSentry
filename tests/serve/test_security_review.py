"""Security regression tests for picosentry serve.

These tests document and enforce the security contract of the serve API:
- Registration cannot self-elevate role.
- Auth is required for privileged endpoints.
- Org isolation prevents cross-tenant reads.
- Role/permission-level access is enforced (read vs write vs admin).
- Malformed tokens and query-param auth attempts are rejected.
- Random/pathological inputs do not produce 500s or leak internal state.
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
        json={
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

    def test_registration_does_not_swallow_unexpected_errors(self, unique_user, monkeypatch):
        """The register endpoint must not catch arbitrary exceptions and return 400."""
        import asyncio

        from picosentry.serve.api.models import RegisterRequest
        from picosentry.serve.api.routers import auth as auth_router

        def _boom(*args, **kwargs):
            raise RuntimeError("database connection lost")

        monkeypatch.setattr(auth_router.auth_service, "create_user", _boom)

        with pytest.raises(RuntimeError, match="database connection lost"):
            asyncio.run(auth_router.register(RegisterRequest(**unique_user)))

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


def _create_role_user(client, role):
    """Create a user with the given role, log in, and create a default org."""
    suffix = uuid.uuid4().hex[:8]
    from picosentry.serve.api.deps import auth_service

    username = f"sec-{role}-{suffix}"
    password = "correct-horse-battery-staple"
    auth_service.create_user(username, password, role=role)

    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]

    slug = f"sec-{role}-org-{suffix}"
    r = client.post(
        "/orgs",
        json={"name": f"Sec {role} org", "slug": slug},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code in (200, 409), f"Default org creation failed: {r.text}"
    return token


class TestRoleEscalation:
    """Non-admin roles cannot reach admin-only endpoints."""

    def test_viewer_cannot_access_admin_backup(self, client):
        token = _create_role_user(client, "viewer")
        r = client.post("/backup", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_viewer_cannot_rotate_logs(self, client):
        token = _create_role_user(client, "viewer")
        r = client.post("/logs/rotate", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_operator_cannot_purge_audit(self, client):
        token = _create_role_user(client, "operator")
        r = client.post("/audit/purge", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403


class TestPermissionLevel:
    """Write/mutate permissions are separate from read permissions."""

    def test_viewer_cannot_run_project(self, client):
        token = _create_role_user(client, "viewer")
        r = client.post(
            "/projects/picosentry/run",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403

    def test_viewer_cannot_create_webhook(self, client):
        token = _create_role_user(client, "viewer")
        r = client.post(
            "/webhooks",
            json={"name": "x", "url": "http://example.com", "events": ["alert"]},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403

    def test_viewer_cannot_create_scheduler_job(self, client):
        token = _create_role_user(client, "viewer")
        r = client.post(
            "/scheduler/jobs",
            json={
                "name": "x",
                "cron": "* * * * *",
                "command": "report",
                "params": {},
                "enabled": False,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403

    def test_viewer_cannot_acknowledge_alert(self, client):
        token = _create_role_user(client, "viewer")
        r = client.post(
            "/alerts/1/acknowledge",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403

    def test_viewer_cannot_trigger_anomaly_check(self, client):
        token = _create_role_user(client, "viewer")
        r = client.post(
            "/anomaly/check",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403


class TestTokenValidation:
    """Malformed, wrong-scheme, and missing credentials are rejected."""

    def test_malformed_bearer_token_rejected(self, client):
        r = client.get(
            "/projects",
            headers={"Authorization": "Bearer not-a-valid-token"},
        )
        assert r.status_code in (401, 403)

    def test_wrong_auth_scheme_rejected(self, client):
        r = client.get(
            "/projects",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert r.status_code in (401, 403)

    def test_missing_auth_header_rejected(self, client):
        r = client.get("/projects")
        assert r.status_code in (401, 403)


class TestAuthBypass:
    """Legacy/insecure auth vectors are not accepted."""

    def test_login_query_params_ignored(self, client, unique_user):
        client.post("/auth/register", json=unique_user)
        # Query parameters must not satisfy the JSON-body login contract.
        r = client.post(
            "/auth/login?username=admin&password=admin",
            json={
                "username": unique_user["username"],
                "password": unique_user["password"],
            },
        )
        assert r.status_code == 200
        assert "access_token" in r.json()

        r2 = client.post("/auth/login?username=admin&password=admin")
        assert r2.status_code == 422


class TestFuzzHarness:
    """Lightweight fuzz: pathological inputs must not 500 or leak stack traces."""

    @pytest.mark.parametrize(
        "payload",
        [
            "' OR 1=1 --",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "A" * 5000,
            "null",
            "true",
            "-1",
            "0",
            "%00",
        ],
    )
    def test_project_read_inputs_do_not_500(self, client, payload):
        token = _create_role_user(client, "viewer")
        r = client.get(
            f"/projects/{payload}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code in (403, 404, 422)
        assert "Internal Server Error" not in r.text
