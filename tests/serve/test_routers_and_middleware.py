"""Dedicated tests for PicoShogun serve routers and middleware."""

import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
os.environ["PICOSHOGUN_ENV"] = "test"
os.environ["PICOSHOGUN_SECRET_KEY"] = "test-key-for-pytest-at-least-32-bytes!"


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from picosentry.serve.api.server import app

    return TestClient(app)


@pytest.fixture
def viewer_token(client):
    """Create and authenticate a viewer user with a default org."""
    tag = int(time.time() * 1000)
    username = f"viewer_{tag}"
    password = "testpassword123"
    resp = client.post("/auth/register", json={"username": username, "password": password})
    if resp.status_code != 200:
        raise RuntimeError(f"registration failed: {resp.status_code} {resp.text}")
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]

    from picosentry.serve.api.server import auth_service
    from picosentry.serve.services.orgs import Organization

    info = auth_service.validate_token(token)
    if not Organization.list_orgs_for_user(info["id"]):
        Organization.create(name=f"Viewer Org {tag}", slug=f"viewer-org-{tag}", owner_user_id=info["id"])
    return token


@pytest.fixture
def admin_token(client):
    """Create and authenticate an admin user with a default org."""
    tag = int(time.time() * 1000)
    username = f"admin_{tag}"
    password = "testpassword123"
    from picosentry.serve.api.server import auth_service
    from picosentry.serve.services.orgs import Organization

    auth_service.create_user(username, password, role="admin")
    token = auth_service.authenticate(username, password)
    assert token
    info = auth_service.validate_token(token)
    Organization.create(name=f"Admin Org {tag}", slug=f"admin-org-{tag}", owner_user_id=info["id"])
    return token


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class TestAuthRouter:
    """Dedicated tests for /auth routes beyond the existing regression suite."""

    def test_login_requires_existing_user(self, client):
        resp = client.post("/auth/login", json={"username": "nosuchuser", "password": "wrong"})
        assert resp.status_code == 401

    def test_create_api_key_requires_auth(self, client):
        resp = client.post("/auth/api-key", json={"name": "test", "permissions": "read"})
        assert resp.status_code in (401, 403)

    def test_create_api_key_roundtrip(self, client, viewer_token):
        resp = client.post(
            "/auth/api-key", json={"name": "test-key", "permissions": "read"}, headers=_headers(viewer_token)
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["permissions"] == "read"
        assert "api_key" in data

    def test_create_api_key_rejects_invalid_permissions(self, client, viewer_token):
        resp = client.post("/auth/api-key", json={"name": "bad", "permissions": "hax"}, headers=_headers(viewer_token))
        assert resp.status_code == 200, resp.text
        assert resp.json()["api_key"] is None

    def test_revoke_api_key_404_for_other_user(self, client, admin_token):
        # Admin revoking key id 99999 should 404.
        resp = client.delete("/auth/api-key/99999", headers=_headers(admin_token))
        assert resp.status_code == 404


class TestAdminRouter:
    """Dedicated tests for /admin routes."""

    def test_admin_backup_forbidden_to_viewer(self, client, viewer_token):
        resp = client.post("/backup", headers=_headers(viewer_token))
        assert resp.status_code == 403

    def test_admin_backup_allowed_to_admin(self, client, admin_token):
        resp = client.post("/backup", headers=_headers(admin_token))
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["status"] == "backup_created"
        assert "path" in data

    def test_admin_logs_stats_allowed_to_admin(self, client, admin_token):
        resp = client.get("/logs/stats", headers=_headers(admin_token))
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "directory" in data
        assert "total_size_mb" in data


class TestProjectsRouter:
    """Dedicated tests for /projects routes."""

    def test_list_projects_requires_auth(self, client):
        resp = client.get("/projects")
        assert resp.status_code in (401, 403)

    def test_list_projects_returns_list(self, client, viewer_token):
        resp = client.get("/projects", headers=_headers(viewer_token))
        assert resp.status_code == 200, resp.text
        assert isinstance(resp.json(), list)

    def test_get_missing_project_404(self, client, viewer_token):
        resp = client.get("/projects/nonexistent-project", headers=_headers(viewer_token))
        assert resp.status_code == 404

    def test_run_missing_project_403_or_404(self, client, viewer_token):
        resp = client.post("/projects/nonexistent-project/run", json={}, headers=_headers(viewer_token))
        assert resp.status_code in (403, 404)


class TestMiddleware:
    """Dedicated tests for security/request middleware."""

    def test_request_id_header_propagates(self, client):
        rid = "my-request-id-123"
        resp = client.get("/health", headers={"X-Request-ID": rid})
        assert resp.status_code == 200
        assert resp.headers.get("X-Request-ID") == rid

    def test_request_id_is_generated_when_absent(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert "X-Request-ID" in resp.headers
        assert resp.headers["X-Request-ID"]

    def test_security_headers_present(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "Content-Security-Policy" in resp.headers
        assert "Strict-Transport-Security" in resp.headers

    def test_request_timeout_middleware_returns_504(self, client):
        # A slow endpoint should be cut off. We simulate by monkey-patching
        # the timeout middleware to a very short value and hitting a sleep endpoint.
        from fastapi.testclient import TestClient

        from picosentry.serve.api.server import app
        from picosentry.serve.middleware.request_timeout import RequestTimeoutMiddleware

        # Wrap the existing app with a 1-second timeout middleware.
        short_app = RequestTimeoutMiddleware(app, timeout_seconds=1)
        short_client = TestClient(short_app)

        @app.get("/__slow_for_middleware_test")
        async def _slow():
            import asyncio

            await asyncio.sleep(5)
            return {"ok": True}

        resp = short_client.get("/__slow_for_middleware_test")
        assert resp.status_code == 504, resp.text
        assert "timed out" in resp.json()["error"].lower()

    def test_request_size_limit_blocks_large_body(self, client):
        # The server mounts RequestSizeLimitMiddleware at 10MB.
        big = "x" * (11 * 1024 * 1024)
        resp = client.post("/auth/login", data=big)
        assert resp.status_code in (413, 422, 400)
