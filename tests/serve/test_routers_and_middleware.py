"""Dedicated tests for PicoShogun serve routers and middleware."""

import os
import sys
import time
from pathlib import Path

import pytest

from fastapi.testclient import TestClient

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
    if resp.status_code != 201:
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
        resp = client.post("/auth/login", json={"username": "nosuchuser", "password": "wrong-password"})
        assert resp.status_code == 401

    def test_login_rejects_short_password_at_validation(self, client):
        # min_length=8 is enforced at the model layer (docs always claimed 8).
        resp = client.post("/auth/login", json={"username": "nosuchuser", "password": "short"})
        assert resp.status_code == 422

    def test_register_rejects_short_password(self, client):
        tag = int(time.time() * 1000)
        resp = client.post("/auth/register", json={"username": f"shortpw_{tag}", "password": "short"})
        assert resp.status_code == 422

    def test_create_api_key_requires_auth(self, client):
        resp = client.post("/auth/api-key", json={"name": "test", "permissions": "read"})
        assert resp.status_code in (401, 403)

    def test_create_api_key_roundtrip(self, client, viewer_token):
        resp = client.post(
            "/auth/api-key", json={"name": "test-key", "permissions": "read"}, headers=_headers(viewer_token)
        )
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["permissions"] == "read"
        assert "api_key" in data

    def test_create_api_key_rejects_invalid_permissions(self, client, viewer_token):
        resp = client.post("/auth/api-key", json={"name": "bad", "permissions": "hax"}, headers=_headers(viewer_token))
        assert resp.status_code == 422, resp.text

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

        # Wrap the existing app with a short timeout middleware. The endpoint
        # sleeps well past the timeout; values are small so the test stays
        # fast — only the sleep > timeout relationship is load-bearing.
        short_app = RequestTimeoutMiddleware(app, timeout_seconds=0.5)
        short_client = TestClient(short_app)

        @app.get("/__slow_for_middleware_test")
        async def _slow():
            import asyncio

            await asyncio.sleep(2)
            return {"ok": True}

        resp = short_client.get("/__slow_for_middleware_test")
        assert resp.status_code == 504, resp.text
        assert "timed out" in resp.json()["error"].lower()

    def test_request_size_limit_blocks_large_body(self, client):
        # The server mounts RequestSizeLimitMiddleware at 10MB.
        big = "x" * (11 * 1024 * 1024)
        resp = client.post("/auth/login", data=big)
        assert resp.status_code in (413, 422, 400)


class TestMFAEnrollHardening:
    """MFA enroll requires the account password and an explicit replace confirm."""

    PASSWORD = "correct-horse-battery-staple"

    @pytest.fixture
    def enrolled_viewer(self, client):
        tag = int(time.time() * 1000)
        username = f"mfa_{tag}"
        resp = client.post("/auth/register", json={"username": username, "password": self.PASSWORD})
        assert resp.status_code == 201, resp.text
        resp = client.post("/auth/login", json={"username": username, "password": self.PASSWORD})
        assert resp.status_code == 200, resp.text
        return {"username": username, "token": resp.json()["access_token"]}

    def test_enroll_without_password_is_422(self, client, enrolled_viewer):
        resp = client.post("/auth/mfa/enroll", json={}, headers=_headers(enrolled_viewer["token"]))
        assert resp.status_code == 422

    def test_enroll_with_wrong_password_is_401(self, client, enrolled_viewer):
        resp = client.post(
            "/auth/mfa/enroll", json={"password": "wrong-password"}, headers=_headers(enrolled_viewer["token"])
        )
        assert resp.status_code == 401

    def test_enroll_with_password_succeeds(self, client, enrolled_viewer):
        resp = client.post(
            "/auth/mfa/enroll", json={"password": self.PASSWORD}, headers=_headers(enrolled_viewer["token"])
        )
        assert resp.status_code == 200, resp.text
        assert "secret" in resp.json()

    def test_reenroll_without_confirm_replace_is_409(self, client, enrolled_viewer):
        first = client.post(
            "/auth/mfa/enroll", json={"password": self.PASSWORD}, headers=_headers(enrolled_viewer["token"])
        )
        assert first.status_code == 200
        second = client.post(
            "/auth/mfa/enroll", json={"password": self.PASSWORD}, headers=_headers(enrolled_viewer["token"])
        )
        assert second.status_code == 409

    def test_reenroll_with_confirm_replace_succeeds(self, client, enrolled_viewer):
        first = client.post(
            "/auth/mfa/enroll", json={"password": self.PASSWORD}, headers=_headers(enrolled_viewer["token"])
        )
        assert first.status_code == 200
        second = client.post(
            "/auth/mfa/enroll",
            json={"password": self.PASSWORD, "confirm_replace": True},
            headers=_headers(enrolled_viewer["token"]),
        )
        assert second.status_code == 200, second.text
        assert second.json()["secret"] != first.json()["secret"]

    def test_stolen_token_cannot_enroll_without_password(self, client, enrolled_viewer):
        # The core takeover scenario: a valid bearer token alone is not enough.
        resp = client.post(
            "/auth/mfa/enroll", json={"confirm_replace": True}, headers=_headers(enrolled_viewer["token"])
        )
        assert resp.status_code == 422


class TestWebAuthnRegisterHardening:
    """Passkey enrollment requires the account password (same class as TOTP enroll)."""

    PASSWORD = "correct-horse-battery-staple"

    @pytest.fixture
    def viewer_with_token(self, client):
        tag = int(time.time() * 1000)
        username = f"wauth_{tag}"
        resp = client.post("/auth/register", json={"username": username, "password": self.PASSWORD})
        assert resp.status_code == 201, resp.text
        resp = client.post("/auth/login", json={"username": username, "password": self.PASSWORD})
        return {"username": username, "token": resp.json()["access_token"]}

    def test_register_challenge_without_password_is_422(self, client, viewer_with_token):
        resp = client.post("/auth/webauthn/register-challenge", json={}, headers=_headers(viewer_with_token["token"]))
        assert resp.status_code == 422

    def test_register_challenge_with_wrong_password_is_401(self, client, viewer_with_token):
        resp = client.post(
            "/auth/webauthn/register-challenge",
            json={"password": "wrong-password"},
            headers=_headers(viewer_with_token["token"]),
        )
        assert resp.status_code == 401

    def test_register_verify_without_password_is_422(self, client, viewer_with_token):
        resp = client.post(
            "/auth/webauthn/register-verify",
            json={"challenge": "x", "credential": {}},
            headers=_headers(viewer_with_token["token"]),
        )
        assert resp.status_code == 422


class TestWebAuthnNoEnumeration:
    """authenticate-challenge must not distinguish known from unknown usernames."""

    PASSWORD = "correct-horse-battery-staple"

    def test_unknown_user_gets_same_shaped_challenge(self, client):
        tag = int(time.time() * 1000)
        resp = client.post("/auth/webauthn/authenticate-challenge", json={"username": f"ghost_{tag}"})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["challenge"]
        assert "options" in body

    def test_known_user_without_passkeys_same_shape(self, client):
        tag = int(time.time() * 1000)
        username = f"nopass_{tag}"
        resp = client.post("/auth/register", json={"username": username, "password": self.PASSWORD})
        assert resp.status_code == 201, resp.text
        resp = client.post("/auth/webauthn/authenticate-challenge", json={"username": username})
        assert resp.status_code == 200, resp.text
        assert set(resp.json().keys()) == {"challenge", "options"}


class TestTokenRevocation:
    """Only the caller's own presented token may be revoked."""

    PASSWORD = "correct-horse-battery-staple"

    def _token_pair(self, client):
        tag = int(time.time() * 1000)
        tokens = []
        for name in (f"revoke_a_{tag}", f"revoke_b_{tag}"):
            resp = client.post("/auth/register", json={"username": name, "password": self.PASSWORD})
            assert resp.status_code == 201, resp.text
            resp = client.post("/auth/login", json={"username": name, "password": self.PASSWORD})
            assert resp.status_code == 200, resp.text
            tokens.append(resp.json()["access_token"])
        return tokens

    def test_revoke_own_token(self, client):
        mine, _ = self._token_pair(client)
        from picosentry.serve.api.server import auth_service

        payload = auth_service.validate_token(mine)
        resp = client.post("/auth/revoke", json={"jti": payload["jti"]}, headers=_headers(mine))
        assert resp.status_code == 200, resp.text
        assert resp.json()["revoked"] is True
        # The revoked token no longer authenticates.
        probe = client.post("/auth/api-key", json={"name": "probe"}, headers=_headers(mine))
        assert probe.status_code == 401

    def test_revoke_foreign_jti_is_403(self, client):
        mine, theirs = self._token_pair(client)
        from picosentry.serve.api.server import auth_service

        foreign_jti = auth_service.validate_token(theirs)["jti"]
        resp = client.post("/auth/revoke", json={"jti": foreign_jti}, headers=_headers(mine))
        assert resp.status_code == 403
        # Victim's token still works.
        probe = client.post("/auth/api-key", json={"name": "probe"}, headers=_headers(theirs))
        assert probe.status_code == 201

    def test_revoke_with_api_key_auth_is_403(self, client, viewer_token):
        # API-key callers present no jti, so they cannot revoke JWTs.
        resp = client.post("/auth/api-key", json={"name": "rk", "permissions": "read"}, headers=_headers(viewer_token))
        assert resp.status_code == 201, resp.text
        api_key = resp.json()["api_key"]
        resp = client.post("/auth/revoke", json={"jti": "anything"}, headers={"X-API-Key": api_key})
        assert resp.status_code == 403


class TestRateLimitLockDiscipline:
    """The Redis roundtrip must happen outside the global in-memory lock."""

    def test_redis_call_not_under_global_lock(self):
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route

        from picosentry.serve.middleware.rate_limit import RateLimitMiddleware

        async def ok(request):
            return JSONResponse({"ok": True})

        holder = {}

        class _ProbeBackend:
            def record_and_count(self, bucket_type, bucket_key):
                mw = holder["mw"]
                acquired = mw._lock.acquire(blocking=False)
                assert acquired, "Redis call serialized behind the global rate-limit lock"
                mw._lock.release()
                return 1

        star = Starlette(routes=[Route("/", ok, methods=["GET"])])
        mw = RateLimitMiddleware(star, backend_instance=_ProbeBackend(), exempt_paths=set())
        holder["mw"] = mw

        resp = TestClient(mw).get("/")
        assert resp.status_code == 200

    def test_memory_path_still_limits(self):
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route

        from picosentry.serve.middleware.rate_limit import RateLimitMiddleware

        async def ok(request):
            return JSONResponse({"ok": True})

        star = Starlette(routes=[Route("/", ok, methods=["GET"])])
        mw = RateLimitMiddleware(star, max_requests_per_ip=2, window=60, exempt_paths=set())
        client = TestClient(mw)
        assert client.get("/").status_code == 200
        assert client.get("/").status_code == 200
        resp = client.get("/")
        assert resp.status_code == 429
        assert resp.headers.get("Retry-After")


@pytest.fixture
def operator_token(client):
    """Create and authenticate an operator user with a default org."""
    tag = int(time.time() * 1000)
    username = f"operator_{tag}"
    password = "testpassword123"
    from picosentry.serve.api.server import auth_service
    from picosentry.serve.services.orgs import Organization

    auth_service.create_user(username, password, role="operator")
    token = auth_service.authenticate(username, password)
    assert token
    info = auth_service.validate_token(token)
    Organization.create(name=f"Operator Org {tag}", slug=f"operator-org-{tag}", owner_user_id=info["id"])
    return token


class TestAnomalyRuleMutationSurface:
    """WO5.0.0-022: anomaly rules are a global singleton — only admins mutate them."""

    def test_operator_patch_rules_forbidden(self, client, operator_token):
        resp = client.patch("/anomaly/rules/health_degraded", json={"threshold": 2}, headers=_headers(operator_token))
        assert resp.status_code == 403

    def test_admin_patch_on_read_only_config_is_clear_500(self, client, admin_token, monkeypatch, tmp_path):
        import picosentry.serve.services.anomaly_detector as ad_mod
        from picosentry.serve.api.server import anomaly_detector

        # Parent path is a file: mkdir/open raise OSError regardless of privileges.
        blocker = tmp_path / "blocker"
        blocker.write_text("not a dir")
        monkeypatch.setattr(ad_mod, "CONFIG_PATH", blocker / "rules.json")

        rule = next(r for r in anomaly_detector.rules if r.id == "health_degraded")
        before = (rule.enabled, rule.threshold)
        try:
            resp = client.patch(
                "/anomaly/rules/health_degraded", json={"enabled": False}, headers=_headers(admin_token)
            )
            assert resp.status_code == 500
            assert "not writable" in resp.text
        finally:
            rule.enabled, rule.threshold = before

    def test_admin_patch_still_allowed(self, client, admin_token, monkeypatch, tmp_path):
        import picosentry.serve.services.anomaly_detector as ad_mod
        from picosentry.serve.api.server import anomaly_detector

        # The real repo config is never touched: saves go to tmp_path.
        monkeypatch.setattr(ad_mod, "CONFIG_PATH", tmp_path / "rules.json")
        rule = next(r for r in anomaly_detector.rules if r.id == "health_degraded")
        before = (rule.enabled, rule.threshold)
        try:
            resp = client.patch(
                "/anomaly/rules/health_degraded", json={"threshold": 1.5}, headers=_headers(admin_token)
            )
            assert resp.status_code == 200, resp.text
            assert resp.json()["threshold"] == 1.5
        finally:
            rule.enabled, rule.threshold = before


class TestSchedulerJobNameConflict:
    """WO5.0.0-021: same name + different config -> 409, not silent stale config."""

    def test_conflicting_config_rejected_409(self, client, admin_token):
        from picosentry.serve.services.scheduler import scheduler

        tag = int(time.time() * 1000)
        body = {"name": f"conflict_job_{tag}", "cron": "0 2 * * *", "command": "cleanup"}
        resp = client.post("/scheduler/jobs", json=body, headers=_headers(admin_token))
        assert resp.status_code == 201, resp.text
        job_id = resp.json()["job_id"]
        try:
            dup = dict(body, cron="*/5 * * * *")
            resp = client.post("/scheduler/jobs", json=dup, headers=_headers(admin_token))
            assert resp.status_code == 409
            assert "different config" in resp.text

            same = client.post("/scheduler/jobs", json=body, headers=_headers(admin_token))
            assert same.status_code == 201
            assert same.json()["job_id"] == job_id
        finally:
            scheduler.remove_job(job_id)

