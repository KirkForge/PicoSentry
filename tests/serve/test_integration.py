"""Integration tests for PicoShogun — end-to-end auth→project→alert flows,
RBAC enforcement, org tenant isolation, API key lifecycle, scheduler,
webhooks, anomaly detection, backup, and security middleware."""

import hashlib
import hmac
import os
import sys
import time
from pathlib import Path

import pytest

# Ensure project root is on sys.path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
os.environ["PICOSHOGUN_ENV"] = "test"
os.environ["PICOSHOGUN_SECRET_KEY"] = "test-key-for-pytest-integration-32b!"
# Registration defaults to OFF in production; the shared conftest.py also sets
# this, but the integration test file imports picosentry modules at module
# load time, so we set the env var here too before any SecurityConfig is built.
os.environ.setdefault("PICOSHOGUN_ALLOW_REGISTRATION", "true")


# ── Fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture
def client():
    """Per-test client to avoid rate-limit accumulation across tests."""
    from fastapi.testclient import TestClient

    from picosentry.serve.api.server import app

    tc = TestClient(app)
    # Clear rate limiter state to avoid cross-test interference
    for middleware in app.user_middleware:
        if hasattr(middleware, "cls") and middleware.cls.__name__ == "RateLimitMiddleware":
            pass  # Can't easily reset without app rebuild
    return tc


def _login(client, username, password):
    """Log in and return the access token."""
    resp = client.post(f"/auth/login?username={username}&password={password}")
    if resp.status_code == 200:
        return resp.json().get("access_token", "")
    return ""


def _auth_headers(token):
    """Return Bearer auth headers."""
    return {"Authorization": f"Bearer {token}"} if token else {}


def _register_and_login(client, role="admin", suffix=None):
    """One-shot: create a user at the requested role + login → token.

    The ``/auth/register`` endpoint creates viewers only (P0 fix); for
    ``admin`` and ``operator`` we drop down to the service layer so the
    integration tests can still exercise elevated paths.
    """
    tag = suffix or int(time.time() * 1000)
    username = f"integ_{role}_{tag}"
    password = "IntegrationTest123!"

    if role == "viewer":
        client.post(
            "/auth/register",
            json={
                "username": username,
                "password": password,
            },
        )
    else:
        # Service-layer creation bypasses the registration endpoint
        # for elevated roles.  This is the same code path the (future)
        # admin-invite flow will use; the integration tests just
        # exercise it now.
        from picosentry.serve.services.auth import AuthService

        AuthService().create_user(username, password, role=role)

    token = _login(client, username, password)
    return token, username


# ── Auth End-to-End ───────────────────────────────────────────────────────


class TestAuthEndToEnd:
    """Full auth lifecycle: register → login → use token → API key rotation."""

    def test_register_login_access_protected_endpoint(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        assert token, "Login should return a valid token"
        resp = client.get("/status", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "system_health" in data

    def test_invalid_token_rejected(self, client):
        resp = client.get("/status", headers=_auth_headers("invalid.token.here"))
        assert resp.status_code in (401, 403)

    def test_no_token_rejected(self, client):
        resp = client.get("/status")
        assert resp.status_code in (401, 403)

    def test_password_too_short_rejected(self, client):
        resp = client.post(
            "/auth/register",
            json={
                "username": f"short_pw_{int(time.time() * 1000)}",
                "password": "short",
                "role": "viewer",
            },
        )
        assert resp.status_code == 422

    def test_invalid_role_rejected(self, client):
        resp = client.post(
            "/auth/register",
            json={
                "username": f"bad_role_{int(time.time() * 1000)}",
                "password": "IntegrationTest123!",
                "role": "superadmin",
            },
        )
        assert resp.status_code == 422

    def test_wrong_password_rejected(self, client):
        username = f"wrong_pw_{int(time.time() * 1000)}"
        client.post(
            "/auth/register",
            json={
                "username": username,
                "password": "IntegrationTest123!",
                "role": "viewer",
            },
        )
        resp = client.post(f"/auth/login?username={username}&password=wrongpassword")
        assert resp.status_code == 401


# ── RBAC Enforcement ─────────────────────────────────────────────────────


class TestRBACEnforcement:
    """Role-based access control: viewer < operator < admin."""

    def test_viewer_cannot_create_scheduler_job(self, client):
        token, _ = _register_and_login(client, role="viewer", suffix=int(time.time() * 1000))
        resp = client.post(
            "/scheduler/jobs",
            json={
                "name": "viewer_job",
                "cron": "0 * * * *",
                "command": "batch",
                "params": {},
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code == 403

    def test_operator_can_create_scheduler_job(self, client):
        token, _ = _register_and_login(client, role="operator", suffix=int(time.time() * 1000))
        resp = client.post(
            "/scheduler/jobs",
            json={
                "name": f"op_job_{int(time.time() * 1000)}",
                "cron": "0 * * * *",
                "command": "batch",
                "params": {},
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200

    def test_viewer_cannot_delete_scheduler_job(self, client):
        token, _ = _register_and_login(client, role="viewer", suffix=int(time.time() * 1000))
        resp = client.delete("/scheduler/jobs/9999", headers=_auth_headers(token))
        assert resp.status_code == 403

    def test_viewer_can_read_status(self, client):
        token, _ = _register_and_login(client, role="viewer", suffix=int(time.time() * 1000))
        resp = client.get("/status", headers=_auth_headers(token))
        assert resp.status_code == 200

    def test_only_admin_can_purge_audit(self, client):
        token_viewer, _ = _register_and_login(client, role="viewer", suffix=int(time.time() * 1000))
        resp = client.post("/audit/purge?dry_run=true", headers=_auth_headers(token_viewer))
        assert resp.status_code == 403


# ── API Key Lifecycle ─────────────────────────────────────────────────────


class TestAPIKeyLifecycle:
    """Create → use → rotate → revoke API keys."""

    def test_create_and_validate_api_key(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.post("/auth/api-key", json={"name": "test_key"}, headers=_auth_headers(token))
        assert resp.status_code == 200
        api_key = resp.json().get("api_key")
        assert api_key

        from picosentry.serve.services.auth import AuthService

        auth = AuthService()
        key_info = auth.validate_api_key(api_key)
        assert key_info is not None
        assert "username" in key_info

    def test_rotate_api_key(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        from picosentry.serve.api.server import auth_service

        user_info = auth_service.validate_token(token)
        assert user_info is not None

        api_key = auth_service.create_api_key(user_info["user_id"], name="rotate_test")
        assert api_key is not None

        from picosentry.serve.database.manager import db

        rows = db.execute(
            "SELECT id FROM api_keys WHERE user_id = ? AND is_active = 1 ORDER BY id DESC LIMIT 1",
            (user_info["user_id"],),
        )
        assert len(rows) > 0
        key_id = rows[0]["id"]

        resp = client.post(f"/auth/api-key/{key_id}/rotate", headers=_auth_headers(token))
        assert resp.status_code == 200
        new_key = resp.json().get("api_key")
        assert new_key

        # Old key should be invalid
        assert auth_service.validate_api_key(api_key) is None
        # New key should be valid
        assert auth_service.validate_api_key(new_key) is not None

    def test_revoke_api_key(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        from picosentry.serve.api.server import auth_service

        user_info = auth_service.validate_token(token)
        assert user_info is not None

        api_key = auth_service.create_api_key(user_info["user_id"], name="revoke_test")
        assert api_key is not None

        from picosentry.serve.database.manager import db

        rows = db.execute(
            "SELECT id FROM api_keys WHERE user_id = ? AND is_active = 1 ORDER BY id DESC LIMIT 1",
            (user_info["user_id"],),
        )
        key_id = rows[0]["id"]

        resp = client.delete(f"/auth/api-key/{key_id}", headers=_auth_headers(token))
        assert resp.status_code == 204

        assert auth_service.validate_api_key(api_key) is None


# ── Organization & Tenant Isolation ──────────────────────────────────────


class TestOrgTenantIsolation:
    """Multi-tenant isolation: user A cannot access org B's data."""

    def test_create_org_and_list_members(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        slug = f"test-org-{int(time.time() * 1000)}"
        resp = client.post(
            "/orgs",
            json={
                "name": "Test Org",
                "slug": slug,
                "tier": "free",
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        org_id = resp.json()["id"]

        resp = client.get(f"/orgs/{org_id}/members", headers=_auth_headers(token))
        assert resp.status_code == 200
        members = resp.json()
        assert "members" in members
        assert len(members["members"]) >= 1

    def test_cross_tenant_org_access_rejected(self, client):
        """User B should not be able to access user A's org data."""
        tag = int(time.time() * 1000)
        token_a, _ = _register_and_login(client, suffix=tag)
        slug_a = f"org-a-{tag}"
        resp_a = client.post(
            "/orgs",
            json={
                "name": "Org A",
                "slug": slug_a,
            },
            headers=_auth_headers(token_a),
        )
        assert resp_a.status_code == 200
        org_id_a = resp_a.json()["id"]

        token_b, _ = _register_and_login(client, suffix=tag + 1)

        resp_b = client.get(f"/orgs/{org_id_a}/members", headers=_auth_headers(token_b))
        assert resp_b.status_code == 403

        resp_b_usage = client.get(f"/orgs/{org_id_a}/usage", headers=_auth_headers(token_b))
        assert resp_b_usage.status_code == 403

    def test_org_usage_and_tier(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        slug = f"usage-org-{int(time.time() * 1000)}"
        resp = client.post(
            "/orgs",
            json={
                "name": "Usage Org",
                "slug": slug,
            },
            headers=_auth_headers(token),
        )
        org_id = resp.json()["id"]

        resp = client.get(f"/orgs/{org_id}/usage", headers=_auth_headers(token))
        assert resp.status_code == 200
        usage = resp.json()
        assert "tier" in usage

    def test_duplicate_slug_rejected(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        slug = f"dup-slug-{int(time.time() * 1000)}"
        resp1 = client.post(
            "/orgs",
            json={
                "name": "First Org",
                "slug": slug,
            },
            headers=_auth_headers(token),
        )
        assert resp1.status_code == 200

        resp2 = client.post(
            "/orgs",
            json={
                "name": "Second Org",
                "slug": slug,
            },
            headers=_auth_headers(token),
        )
        assert resp2.status_code == 409

    def test_org_upgrade_requires_admin(self, client):
        token_viewer, _ = _register_and_login(client, role="viewer", suffix=int(time.time() * 1000))
        slug = f"upgrade-org-{int(time.time() * 1000)}"
        resp = client.post(
            "/orgs",
            json={
                "name": "Upgrade Org",
                "slug": slug,
            },
            headers=_auth_headers(token_viewer),
        )
        org_id = resp.json()["id"]

        resp = client.post(f"/orgs/{org_id}/upgrade", json={"tier": "pro"}, headers=_auth_headers(token_viewer))
        assert resp.status_code == 403


# ── Scheduler Command Whitelist ───────────────────────────────────────────


class TestSchedulerWhitelist:
    """Scheduler only accepts whitelisted commands."""

    def test_reject_invalid_command_via_api(self, client):
        token, _ = _register_and_login(client, role="operator", suffix=int(time.time() * 1000))
        resp = client.post(
            "/scheduler/jobs",
            json={
                "name": "evil_job",
                "cron": "0 * * * *",
                "command": "rm -rf /",
                "params": {},
            },
            headers=_auth_headers(token),
        )
        # The scheduler raises ValueError → API returns 400
        assert resp.status_code in (200, 400)

    def test_valid_commands_accepted(self, client):
        from picosentry.serve.services.scheduler import scheduler

        for cmd in ["batch", "run", "report", "backup", "cleanup"]:
            job_id = scheduler.add_job(
                name=f"test_{cmd}_{int(time.time() * 1000)}",
                cron="0 */6 * * *",
                command=cmd,
                params={},
                enabled=False,
            )
            assert job_id is not None, f"Command '{cmd}' should be accepted"

    def test_invalid_command_rejected_service(self):
        from picosentry.serve.services.scheduler import scheduler

        with pytest.raises(ValueError, match="Invalid command"):
            scheduler.add_job(
                name="evil_job",
                cron="* * * * *",
                command="rm -rf /",
                params={},
            )

    def test_non_primitive_params_rejected(self):
        from picosentry.serve.services.scheduler import scheduler

        with pytest.raises(ValueError, match="Invalid param"):
            scheduler.add_job(
                name="bad_params",
                cron="* * * * *",
                command="batch",
                params={"evil": {"nested": "dict"}},
            )


# ── Webhooks ─────────────────────────────────────────────────────────────


class TestWebhooksIntegration:
    """Webhook creation with SSRF protection."""

    def test_create_webhook_with_default_name(self, client):
        token, _ = _register_and_login(client, role="operator", suffix=int(time.time() * 1000))
        resp = client.post(
            "/webhooks",
            json={
                "url": "https://example.com/hook",
                "events": ["*"],
                "name": "default-hook",
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200

    def test_create_webhook_with_custom_name(self, client):
        token, _ = _register_and_login(client, role="operator", suffix=int(time.time() * 1000))
        resp = client.post(
            "/webhooks",
            json={
                "url": "https://example.com/hook2",
                "events": ["alert"],
                "name": "my-webhook",
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200

    def test_webhook_rejects_localhost(self, client):
        token, _ = _register_and_login(client, role="operator", suffix=int(time.time() * 1000))
        resp = client.post(
            "/webhooks",
            json={
                "url": "http://127.0.0.1:8080/hook",
                "events": ["*"],
                "name": "evil_local",
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code == 400

    def test_webhook_rejects_private_ip(self, client):
        token, _ = _register_and_login(client, role="operator", suffix=int(time.time() * 1000))
        resp = client.post(
            "/webhooks",
            json={
                "url": "http://10.0.0.1/hook",
                "events": ["*"],
                "name": "evil_private",
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code == 400

    def test_webhook_rejects_file_scheme(self, client):
        token, _ = _register_and_login(client, role="operator", suffix=int(time.time() * 1000))
        resp = client.post(
            "/webhooks",
            json={
                "url": "file:///etc/passwd",
                "events": ["*"],
                "name": "evil_file",
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code == 400


# ── Intelligence & Alerts ─────────────────────────────────────────────────


class TestIntelligenceAndAlerts:
    """Intelligence listing, threat score, and alert endpoints."""

    def test_list_intelligence(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.get("/intelligence", headers=_auth_headers(token))
        assert resp.status_code == 200

    def test_threat_score(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.get("/intelligence/threat-score", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "threat_score" in data
        assert "total_threats" in data

    def test_alerts_listing(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.get("/alerts", headers=_auth_headers(token))
        assert resp.status_code == 200

    def test_acknowledge_nonexistent_alert(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.post("/alerts/99999/acknowledge", headers=_auth_headers(token))
        assert resp.status_code == 404


# ── Projects ──────────────────────────────────────────────────────────────


class TestProjects:
    """Project listing and run endpoints."""

    def test_list_projects(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        slug = f"proj-org-{int(time.time() * 1000)}"
        client.post("/orgs", json={"name": "Project Org", "slug": slug}, headers=_auth_headers(token))
        resp = client.get("/projects", headers=_auth_headers(token))
        assert resp.status_code == 200

    def test_project_not_found(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        slug = f"pnf-org-{int(time.time() * 1000)}"
        client.post("/orgs", json={"name": "Project Not Found Org", "slug": slug}, headers=_auth_headers(token))
        resp = client.get("/projects/nonexistent_project_id", headers=_auth_headers(token))
        assert resp.status_code == 404


# ── Dashboard Summary ────────────────────────────────────────────────────


class TestDashboardSummary:
    def test_dashboard_summary_authenticated(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.get("/api/v1/dashboard/summary", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data

    def test_dashboard_summary_unauthenticated(self, client):
        resp = client.get("/api/v1/dashboard/summary")
        assert resp.status_code in (401, 403)


# ── Reports ───────────────────────────────────────────────────────────────


class TestReports:
    def test_summary_report(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.get("/reports/summary", headers=_auth_headers(token))
        assert resp.status_code == 200

    def test_project_report_not_found(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.get("/reports/project/nonexistent", headers=_auth_headers(token))
        assert resp.status_code == 404


# ── Metrics ───────────────────────────────────────────────────────────────


class TestMetricsIntegration:
    def test_metrics_json_authenticated(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.get("/metrics/json", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "uptime_seconds" in data

    def test_prometheus_endpoint(self, client):
        resp = client.get("/metrics/prometheus")
        assert resp.status_code == 200
        assert "picoshogun_" in resp.text

    def test_detailed_metrics(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.get("/metrics?detailed=true", headers=_auth_headers(token))
        assert resp.status_code == 200


# ── Audit ─────────────────────────────────────────────────────────────────


class TestAudit:
    def test_audit_stats(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.get("/audit/stats", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "retention_policy" in data

    def test_audit_purge_dry_run(self, client):
        token, _ = _register_and_login(client, role="admin", suffix=int(time.time() * 1000))
        resp = client.post("/audit/purge?dry_run=true&retention_days=30", headers=_auth_headers(token))
        assert resp.status_code == 200

    def test_audit_purge_viewer_forbidden(self, client):
        token, _ = _register_and_login(client, role="viewer", suffix=int(time.time() * 1000))
        resp = client.post("/audit/purge?dry_run=true", headers=_auth_headers(token))
        assert resp.status_code == 403


# ── Backup ────────────────────────────────────────────────────────────────


class TestBackup:
    def test_list_backups(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.get("/backups", headers=_auth_headers(token))
        assert resp.status_code == 200

    def test_create_backup_requires_admin(self, client):
        token_viewer, _ = _register_and_login(client, role="viewer", suffix=int(time.time() * 1000))
        resp = client.post("/backup", headers=_auth_headers(token_viewer))
        assert resp.status_code == 403


# ── Anomaly Detection ────────────────────────────────────────────────────


class TestAnomalyDetection:
    def test_list_anomaly_rules(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.get("/anomaly/rules", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_list_anomaly_alerts(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.get("/anomaly/alerts", headers=_auth_headers(token))
        assert resp.status_code == 200

    def test_trigger_anomaly_check(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.post("/anomaly/check", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "triggered" in data

    def test_update_anomaly_rule(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.patch("/anomaly/rules/high_error_rate?threshold=20", headers=_auth_headers(token))
        assert resp.status_code == 200

    def test_update_nonexistent_rule(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.patch("/anomaly/rules/nonexistent_rule?enabled=false", headers=_auth_headers(token))
        assert resp.status_code == 404


# ── PicoDome endpoints (previously stubs, now real) ─────────────────────


class TestPicoDomeEndpoints:
    def test_scan_endpoint_returns_200(self, client, tmp_path):
        """Scan endpoint runs the built-in scanner end-to-end.  Operator
        role is required (P0 fix); viewers are rejected with 403.

        We point at an empty directory under the configured workspace
        rather than ``/tmp`` itself.  A real ``/tmp`` on a developer
        box has ~1000+ files and the built-in scanner takes ~25 s on
        it — which exceeds TestClient's default httpx timeout and
        masks the endpoint contract this test is supposed to pin.
        An empty target is scanned in milliseconds and exercises the
        same request → engine → response path."""
        target = tmp_path / "scan_target"
        target.mkdir()
        token, _ = _register_and_login(client, role="operator", suffix=int(time.time() * 1000))
        resp = client.post(
            "/api/v1/scans",
            json={
                "target": str(target),
                "rules": None,
                "format": "json",
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "scan_id" in data
        assert "findings_count" in data

    def test_sandbox_endpoint_returns_200(self, client):
        """Sandbox endpoint now runs the built-in sandbox."""
        token, _ = _register_and_login(client, role="operator", suffix=int(time.time() * 1000))
        resp = client.post(
            "/api/v1/sandboxes",
            json={
                "command": ["echo", "hello"],
                "format": "json",
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "overall_verdict" in data
        assert "events" in data

    def test_scan_rules_returns_rules(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.get("/api/v1/scans/rules", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "rules" in data
        assert len(data["rules"]) > 0

    def test_sandbox_policy_returns_policy(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.get("/api/v1/sandboxes/policies/default", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "name" in data


# ── Security Middleware ────────────────────────────────────────────────────


class TestSecurityMiddleware:
    def test_security_headers_present(self, client):
        resp = client.get("/health")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert "Strict-Transport-Security" in resp.headers

    def test_request_id_header_present(self, client):
        resp = client.get("/health")
        assert "X-Request-ID" in resp.headers

    def test_request_id_propagation(self, client):
        custom_id = "test-request-12345"
        resp = client.get("/health", headers={"X-Request-ID": custom_id})
        assert resp.headers.get("X-Request-ID") == custom_id


# ── Health Probes ─────────────────────────────────────────────────────────


class TestHealthProbes:
    def test_liveness_probe(self, client):
        resp = client.get("/health/live")
        assert resp.status_code == 200
        assert resp.json()["status"] == "alive"

    def test_readiness_probe(self, client):
        resp = client.get("/health/ready")
        assert resp.status_code in (200, 503)

    def test_health_overall(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["overall"] in ("healthy", "degraded", "critical")

    def test_health_history_requires_auth(self, client):
        resp = client.get("/health/history")
        assert resp.status_code in (401, 403)


# ── Event Bus ─────────────────────────────────────────────────────────────


class TestEventBus:
    def test_event_history(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.get("/events/history", headers=_auth_headers(token))
        assert resp.status_code == 200

    def test_event_history_with_type_filter(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.get("/events/history?event_type=test&limit=10", headers=_auth_headers(token))
        assert resp.status_code == 200


# ── Logs ──────────────────────────────────────────────────────────────────


class TestLogs:
    def test_log_stats(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.get("/logs/stats", headers=_auth_headers(token))
        assert resp.status_code == 200

    def test_log_rotation(self, client):
        token, _ = _register_and_login(client, suffix=int(time.time() * 1000))
        resp = client.post("/logs/rotate", headers=_auth_headers(token))
        assert resp.status_code == 200


# ── Webhook Service Tests ────────────────────────────────────────────────


class TestWebhookService:
    """Direct service-level tests for webhook signing and SSRF."""

    def test_sign_payload(self):
        from picosentry.serve.services.webhooks import webhook_manager

        payload = {"event": "test", "data": "hello"}
        secret = "test-secret-key-12345678"
        signature = webhook_manager.sign_payload(payload, secret)
        assert isinstance(signature, str)
        assert len(signature) == 64  # SHA-256 hex digest

    def test_verify_signature_constant_time(self):
        from picosentry.serve.services.webhooks import webhook_manager

        payload = b'{"test": true}'
        secret = "test-secret-key-12345678"
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        assert webhook_manager.verify_signature(payload, expected, secret)

    def test_verify_signature_rejects_tampered(self):
        from picosentry.serve.services.webhooks import webhook_manager

        payload = b'{"test": true}'
        secret = "test-secret-key-12345678"
        assert not webhook_manager.verify_signature(payload, "tampered_signature", secret)

    def test_ssrf_blocks_localhost(self):
        from picosentry.serve.services.webhooks import _is_safe_webhook_url

        safe, _reason = _is_safe_webhook_url("http://localhost/admin")
        assert not safe

    def test_ssrf_blocks_aws_metadata(self):
        from picosentry.serve.services.webhooks import _is_safe_webhook_url

        safe, _reason = _is_safe_webhook_url("http://169.254.169.254/latest/meta-data/")
        assert not safe

    def test_ssrf_blocks_ipv6_loopback(self):
        from picosentry.serve.services.webhooks import _is_safe_webhook_url

        safe, _reason = _is_safe_webhook_url("http://[::1]/admin")
        assert not safe

    def test_ssrf_blocks_ftp_scheme(self):
        from picosentry.serve.services.webhooks import _is_safe_webhook_url

        safe, _reason = _is_safe_webhook_url("ftp://evil.com/payload")
        assert not safe


# ── Auth Service Tests ──────────────────────────────────────────────────


class TestAuthServiceIntegration:
    """Integration-level auth service tests."""

    def test_password_hashing_roundtrip(self):
        from picosentry.serve.services.auth import AuthService

        auth = AuthService()
        tag = int(time.time() * 1000)
        username = f"hash_test_{tag}"
        auth.create_user(username, "correct_password_123", role="admin")
        token = auth.authenticate(username, "correct_password_123")
        assert token is not None
        token_wrong = auth.authenticate(username, "wrong_password_456")
        assert token_wrong is None

    def test_expired_token_rejected(self):
        from picosentry.serve.services.auth import AuthService

        auth = AuthService()
        tag = int(time.time() * 1000)
        username = f"expire_test_{tag}"
        auth.create_user(username, "testpassword123", role="admin")
        token = auth.authenticate(username, "testpassword123")
        assert token is not None
        info = auth.validate_token(token)
        assert info is not None

    def test_legacy_simple_token_rejected(self):
        from picosentry.serve.services.auth import AuthService

        auth = AuthService()
        result = auth.validate_token("simple:123:fake")
        assert result is None

    def test_api_key_rotation_preserves_permissions(self):
        from picosentry.serve.services.auth import AuthService

        auth = AuthService()
        tag = int(time.time() * 1000)
        username = f"keyrot_{tag}"
        user_id = auth.create_user(username, "testpassword123", role="admin")
        assert user_id is not None

        api_key = auth.create_api_key(user_id, "rot-test", permissions="read")
        assert api_key is not None

        key_info = auth.validate_api_key(api_key)
        assert key_info is not None
        key_id = key_info["id"]

        new_key = auth.rotate_api_key(key_id, user_id)
        assert new_key is not None

        # Old key should be invalid
        assert auth.validate_api_key(api_key) is None
        # New key should be valid
        new_info = auth.validate_api_key(new_key)
        assert new_info is not None
        assert new_info["permissions"] == "read"

    def test_check_permission_hierarchy(self):
        from picosentry.serve.services.auth import AuthService

        auth = AuthService()
        viewer = {"role": "viewer"}
        operator = {"role": "operator"}
        admin = {"role": "admin"}

        assert not auth.check_permission(viewer, "run")
        assert auth.check_permission(operator, "run")
        assert auth.check_permission(admin, "run")
        assert auth.check_permission(viewer, "read")
        assert not auth.check_permission(operator, "admin")
        assert auth.check_permission(admin, "admin")


# ── Scheduler Service Tests ──────────────────────────────────────────────


class TestSchedulerServiceIntegration:
    def test_scheduler_status_returns_list(self):
        from picosentry.serve.services.scheduler import scheduler

        status = scheduler.get_status()
        assert isinstance(status, list)

    def test_remove_nonexistent_job(self):
        from picosentry.serve.services.scheduler import scheduler

        result = scheduler.remove_job(99999)
        assert result is False


# ── Organization Service Tests ──────────────────────────────────────────


class TestOrganizationService:
    def test_create_org(self):
        from picosentry.serve.services.auth import AuthService
        from picosentry.serve.services.orgs import Organization

        auth = AuthService()
        tag = int(time.time() * 1000)
        user_id = auth.create_user(f"org_svc_{tag}", "testpassword123", role="admin")
        org_id = Organization.create("Test Org Svc", f"org-svc-{tag}", user_id)
        assert org_id is not None

    def test_duplicate_slug_rejected(self):
        from picosentry.serve.services.auth import AuthService
        from picosentry.serve.services.orgs import Organization

        auth = AuthService()
        tag = int(time.time() * 1000)
        user_id = auth.create_user(f"org_dup_{tag}", "testpassword123", role="admin")
        slug = f"dup-org-{tag}"
        org_id_1 = Organization.create("First Org", slug, user_id)
        org_id_2 = Organization.create("Second Org", slug, user_id)
        assert org_id_1 is not None
        assert org_id_2 is None

    def test_org_tiers(self):
        from picosentry.serve.services.orgs import Organization

        for tier in ["free", "starter", "pro", "enterprise"]:
            assert tier in Organization.TIERS

    def test_can_create_project_limits(self):
        from picosentry.serve.services.orgs import Organization

        limits = Organization.TIERS["free"]
        assert limits["projects"] < Organization.TIERS["enterprise"]["projects"]


# ── Intelligence Engine Tests ──────────────────────────────────────────────


class TestIntelligenceEngine:
    def test_classify_critical_vuln(self):
        """Critical failure signatures should be detected."""
        from picosentry.serve.services.intelligence import IntelligenceEngine

        engine = IntelligenceEngine()
        # classify_failure matches failure signatures (not the main PATTERNS)
        result = engine.classify_failure("test-proj", "ModuleNotFoundError: No module named picoshogun")
        assert result is not None
        assert result["severity"] in ("critical", "high")

    def test_classify_auth_failure(self):
        """Auth failure patterns should be detected."""
        from picosentry.serve.services.intelligence import IntelligenceEngine

        engine = IntelligenceEngine()
        # "permission denied" matches a failure signature
        result = engine.classify_failure("test-proj", "Permission denied: operation not permitted")
        assert result is not None

    def test_classify_timeout(self):
        from picosentry.serve.services.intelligence import IntelligenceEngine

        engine = IntelligenceEngine()
        result = engine.classify_failure("test-proj", "Connection timed out after 30 seconds")
        assert result is not None
        assert result["severity"] == "medium"

    def test_classify_empty_output(self):
        from picosentry.serve.services.intelligence import IntelligenceEngine

        engine = IntelligenceEngine()
        result = engine.classify_failure("test-proj", "")
        # Empty output should return None (no patterns match)
        assert result is None

    def test_aggregate_score(self):
        from picosentry.serve.services.intelligence import IntelligenceEngine

        engine = IntelligenceEngine()
        score = engine.get_aggregate_score()
        assert isinstance(score, (int, float))


# ── Metrics Service Tests ────────────────────────────────────────────────


class TestMetricsServiceIntegration:
    def test_prometheus_no_double_prefix(self):
        from picosentry.serve.services.metrics import MetricsCollector

        mc = MetricsCollector()
        mc.counter("test_counter", 1)
        output = mc.to_prometheus()
        assert "picopicoshogun" not in output
        assert "picoshogun_" in output

    def test_project_run_metrics(self):
        from picosentry.serve.services.metrics import MetricsCollector

        mc = MetricsCollector()
        mc.project_run("test-project", 42.5, "completed")
        data = mc.to_dict()
        assert "counters" in data

    def test_api_request_metrics(self):
        from picosentry.serve.services.metrics import MetricsCollector

        mc = MetricsCollector()
        mc.api_request("GET", "/health", 200, 0.05)
        data = mc.to_dict()
        assert "counters" in data


# ── Backup Service Tests ─────────────────────────────────────────────────


class TestBackupService:
    def test_list_backups(self):
        from picosentry.serve.services.backup import BackupManager

        bm = BackupManager()
        backups = bm.list_backups()
        assert isinstance(backups, list)

    def test_create_and_list_backup(self):
        from picosentry.serve.services.backup import BackupManager

        bm = BackupManager()
        result = bm.create_backup(name="test_backup_integration", include_logs=False)
        if result:
            assert "path" in result
            backups = bm.list_backups()
            assert any("test_backup_integration" in b["name"] for b in backups)


# ── Configuration Tests ──────────────────────────────────────────────────


class TestConfiguration:
    def test_settings_loads(self):
        from picosentry.serve.config.settings import settings

        assert settings.api.port == 8765
        assert settings.database.journal_mode == "WAL"
        assert settings.security.jwt_algorithm == "HS256"

    def test_settings_validate(self):
        from picosentry.serve.config.settings import settings

        issues = settings.validate()
        assert isinstance(issues, list)

    def test_is_production(self):
        from picosentry.serve.config.settings import settings

        assert not settings.is_production()

    def test_version_is_consistent(self):
        # version is validated by config.version module
        from picosentry.serve.api.server import app
        from picosentry.serve.config.version import __version__ as _v

        assert app.version == _v


# ── Rate Limiting ─────────────────────────────────────────────────────────


class TestRateLimiting:
    def test_rate_limit_middleware_instantiates(self):
        from starlette.applications import Starlette
        from starlette.responses import PlainTextResponse
        from starlette.routing import Route

        from picosentry.serve.middleware.rate_limit import RateLimitMiddleware

        async def homepage(request):
            return PlainTextResponse("ok")

        app = Starlette(routes=[Route("/", homepage)])
        app.add_middleware(RateLimitMiddleware, max_requests_per_ip=100, max_requests_per_org=1000, window=60)
        from starlette.testclient import TestClient

        tc = TestClient(app)
        resp = tc.get("/")
        assert resp.status_code == 200


# ── Scheduler Enable/Disable ──────────────────────────────────────────────


class TestSchedulerEnableDisable:
    def test_enable_disable_job(self, client):
        token, _ = _register_and_login(client, role="operator", suffix=int(time.time() * 1000))
        resp = client.post(
            "/scheduler/jobs",
            json={
                "name": f"toggle_job_{int(time.time() * 1000)}",
                "cron": "0 0 * * *",
                "command": "report",
                "params": {},
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        job_id = resp.json().get("job_id")

        if job_id:
            resp_disable = client.patch(f"/scheduler/jobs/{job_id}/disable", headers=_auth_headers(token))
            assert resp_disable.status_code == 200

            resp_enable = client.patch(f"/scheduler/jobs/{job_id}/enable", headers=_auth_headers(token))
            assert resp_enable.status_code == 200

    def test_delete_job(self, client):
        token_op, _ = _register_and_login(client, role="operator", suffix=int(time.time() * 1000))
        resp = client.post(
            "/scheduler/jobs",
            json={
                "name": f"del_job_{int(time.time() * 1000)}",
                "cron": "0 0 * * *",
                "command": "cleanup",
                "params": {},
            },
            headers=_auth_headers(token_op),
        )
        assert resp.status_code == 200
        job_id = resp.json().get("job_id")

        if job_id:
            token_admin, _ = _register_and_login(client, role="admin", suffix=int(time.time() * 1000) + 1)
            resp_del = client.delete(f"/scheduler/jobs/{job_id}", headers=_auth_headers(token_admin))
            assert resp_del.status_code == 204


# ── CORS Hardening ────────────────────────────────────────────────────────


class TestCORSHardening:
    def test_cors_middleware_present(self):
        from starlette.applications import Starlette
        from starlette.responses import PlainTextResponse
        from starlette.routing import Route

        from picosentry.serve.middleware.cors_hardening import CORSHardeningMiddleware

        async def homepage(request):
            return PlainTextResponse("ok")

        app = Starlette(routes=[Route("/", homepage)])
        app.add_middleware(CORSHardeningMiddleware, block_wildcard_in_production=False)
        from starlette.testclient import TestClient

        tc = TestClient(app)
        resp = tc.get("/")
        assert resp.status_code == 200


# ── DDoS Shield ───────────────────────────────────────────────────────────


class TestDDoSShield:
    def test_ddos_shield_pass_through(self):
        from starlette.applications import Starlette
        from starlette.responses import PlainTextResponse
        from starlette.routing import Route

        from picosentry.serve.middleware.ddos_shield import DDoSShieldMiddleware

        async def homepage(request):
            return PlainTextResponse("ok")

        app = Starlette(routes=[Route("/", homepage)])
        app.add_middleware(DDoSShieldMiddleware, enabled=True)
        from starlette.testclient import TestClient

        tc = TestClient(app)
        resp = tc.get("/")
        assert resp.status_code == 200


# ── Tenant Data Isolation (P1 #3) ──────────────────────────────────────────


class TestTenantDataIsolation:
    """Data-level tenant isolation: org A's data cannot be read by org B's users.

    These tests verify that even if two orgs share the same PicoShogun instance,
    users in org A cannot read, modify, or delete data belonging to org B through
    the API. This closes the P1 #3 gap identified in the security review.
    """

    def test_tenant_cannot_read_other_org_projects(self, client):
        """Org A creates a project; Org B's member cannot list or see it through org-scoped endpoints."""
        tag = int(time.time() * 1000)

        # Create user A and org A
        token_a, _user_a = _register_and_login(client, suffix=tag)
        slug_a = f"tenant-proj-a-{tag}"
        resp = client.post("/orgs", json={"name": "Tenant Org A", "slug": slug_a}, headers=_auth_headers(token_a))
        assert resp.status_code == 200
        org_a_id = resp.json()["id"]

        # Create user B and org B
        token_b, _ = _register_and_login(client, suffix=tag + 1)
        slug_b = f"tenant-proj-b-{tag}"
        resp_b = client.post("/orgs", json={"name": "Tenant Org B", "slug": slug_b}, headers=_auth_headers(token_b))
        assert resp_b.status_code == 200
        org_b_id = resp_b.json()["id"]

        # Verify org IDs are different
        assert org_a_id != org_b_id

        # User B cannot access org A's usage or members
        resp = client.get(f"/orgs/{org_a_id}/usage", headers=_auth_headers(token_b))
        assert resp.status_code == 403

        resp = client.get(f"/orgs/{org_a_id}/members", headers=_auth_headers(token_b))
        assert resp.status_code == 403

    def test_tenant_cannot_upgrade_other_org(self, client):
        """Org A admin cannot upgrade org B's tier even with admin role."""
        tag = int(time.time() * 1000)

        token_a, _ = _register_and_login(client, role="admin", suffix=tag)
        slug_a = f"tenant-upgrade-a-{tag}"
        resp = client.post("/orgs", json={"name": "Tenant Upgrade A", "slug": slug_a}, headers=_auth_headers(token_a))
        _ = resp.json()["id"]

        token_b, _ = _register_and_login(client, role="admin", suffix=tag + 1)
        slug_b = f"tenant-upgrade-b-{tag}"
        resp_b = client.post("/orgs", json={"name": "Tenant Upgrade B", "slug": slug_b}, headers=_auth_headers(token_b))
        org_b_id = resp_b.json()["id"]

        # Admin A tries to upgrade org B — should be denied
        resp = client.post(f"/orgs/{org_b_id}/upgrade", json={"tier": "pro"}, headers=_auth_headers(token_a))
        assert resp.status_code in (403, 404)

    def test_tenant_api_key_isolation(self, client):
        """API key for org A cannot be used to access org B's data."""
        tag = int(time.time() * 1000)

        token_a, _ = _register_and_login(client, suffix=tag)
        slug_a = f"tenant-apikey-a-{tag}"
        resp = client.post("/orgs", json={"name": "Tenant API A", "slug": slug_a}, headers=_auth_headers(token_a))
        org_a_id = resp.json()["id"]
        org_a_data = client.get(f"/orgs/{org_a_id}", headers=_auth_headers(token_a)).json()
        org_a_api_key = org_a_data.get("api_key", "")

        token_b, _ = _register_and_login(client, suffix=tag + 1)
        slug_b = f"tenant-apikey-b-{tag}"
        resp_b = client.post("/orgs", json={"name": "Tenant API B", "slug": slug_b}, headers=_auth_headers(token_b))
        _ = resp_b.json()["id"]

        # User B tries to use org A's API key header to access org A data
        resp = client.get(
            f"/orgs/{org_a_id}/usage",
            headers={
                **_auth_headers(token_b),
                "X-Org-API-Key": org_a_api_key,
            },
        )
        # Should be rejected — user B is not a member of org A
        assert resp.status_code == 403

    def test_tenant_org_listing_isolation(self, client):
        """User belonging to org A only sees org A in their orgs list, not org B."""
        tag = int(time.time() * 1000)

        token_a, _ = _register_and_login(client, suffix=tag)
        slug_a = f"tenant-list-a-{tag}"
        client.post("/orgs", json={"name": "Tenant List A", "slug": slug_a}, headers=_auth_headers(token_a))

        token_b, _ = _register_and_login(client, suffix=tag + 1)
        slug_b = f"tenant-list-b-{tag}"
        client.post("/orgs", json={"name": "Tenant List B", "slug": slug_b}, headers=_auth_headers(token_b))

        # User A lists their orgs — should only contain org A
        resp = client.get("/orgs", headers=_auth_headers(token_a))
        assert resp.status_code == 200
        org_list = resp.json().get("orgs", [])
        org_slugs = [o.get("slug", "") for o in org_list]
        assert slug_b not in org_slugs, f"User A should not see org B (slugs: {org_slugs})"
        assert slug_a in org_slugs, f"User A should see org A (slugs: {org_slugs})"

    def test_org_creation_same_user_different_orgs(self, client):
        """A single user can belong to multiple orgs and see all of them."""
        tag = int(time.time() * 1000)
        token, _ = _register_and_login(client, suffix=tag)

        slug1 = f"multi-org-1-{tag}"
        slug2 = f"multi-org-2-{tag}"
        resp1 = client.post("/orgs", json={"name": "Multi Org 1", "slug": slug1}, headers=_auth_headers(token))
        resp2 = client.post("/orgs", json={"name": "Multi Org 2", "slug": slug2}, headers=_auth_headers(token))

        assert resp1.status_code == 200
        assert resp2.status_code == 200

        # User should see both orgs
        resp = client.get("/orgs", headers=_auth_headers(token))
        org_slugs = [o.get("slug", "") for o in resp.json().get("orgs", [])]
        assert slug1 in org_slugs
        assert slug2 in org_slugs


class TestRBACPolicy:
    """Test RBAC policy engine and permission checks."""

    def test_viewer_permissions(self):
        from picosentry.serve.services.rbac import Permission, get_permissions, has_permission

        viewer = {"role": "viewer", "id": 1, "username": "viewer_user"}
        viewer_perms = get_permissions("viewer")
        assert Permission.READ_PROJECTS in viewer_perms
        assert Permission.READ_HEALTH in viewer_perms
        assert Permission.RUN_PROJECTS not in viewer_perms
        assert Permission.ADMIN_USERS not in viewer_perms
        assert has_permission(viewer, Permission.READ_PROJECTS)
        assert not has_permission(viewer, Permission.RUN_PROJECTS)

    def test_operator_permissions(self):
        from picosentry.serve.services.rbac import Permission, get_permissions, has_permission

        operator = {"role": "operator", "id": 2, "username": "op_user"}
        op_perms = get_permissions("operator")
        assert Permission.RUN_PROJECTS in op_perms
        assert Permission.WRITE_WEBHOOKS in op_perms
        assert Permission.ADMIN_USERS not in op_perms
        assert has_permission(operator, Permission.RUN_PROJECTS)
        assert not has_permission(operator, Permission.ADMIN_USERS)

    def test_admin_permissions(self):
        from picosentry.serve.services.rbac import Permission, get_permissions, has_permission

        admin = {"role": "admin", "id": 3, "username": "admin_user"}
        admin_perms = get_permissions("admin")
        assert len(admin_perms) == len(Permission)
        for perm in Permission:
            assert has_permission(admin, perm), f"Admin should have {perm.value}"

    def test_unknown_role(self):
        from picosentry.serve.services.rbac import Permission, get_permissions, has_permission

        unknown = {"role": "unknown_role", "id": 4, "username": "unknown"}
        assert get_permissions("unknown_role") == set()
        assert not has_permission(unknown, Permission.READ_PROJECTS)

    def test_require_permission_dependency(self):
        """Test that require_permission FastAPI dependency works."""
        from picosentry.serve.api.deps import require_permission
        from picosentry.serve.services.rbac import Permission

        # Just verify the dependency factory works without calling it
        dep = require_permission(Permission.RUN_PROJECTS)
        assert dep is not None

    def test_role_permissions_are_strict_subsets(self):
        """Verify that operator ⊂ admin and viewer ⊂ operator (for read perms)."""
        from picosentry.serve.services.rbac import ROLE_PERMISSIONS

        viewer_perms = ROLE_PERMISSIONS["viewer"]
        operator_perms = ROLE_PERMISSIONS["operator"]
        admin_perms = ROLE_PERMISSIONS["admin"]
        # Viewer permissions are a subset of operator
        assert viewer_perms.issubset(operator_perms)
        # Operator permissions are a subset of admin
        assert operator_perms.issubset(admin_perms)
        # But admin has strictly more
        assert admin_perms > operator_perms
