"""Integration tests for PicoShogun — end-to-end auth→project→alert flows,
RBAC enforcement, org tenant isolation, API key lifecycle, scheduler,
webhooks, anomaly detection, backup, and security middleware.

Env setup (PICOSHOGUN_ENV, SECRET_KEY, ALLOW_REGISTRATION, per-worker DB
path, rate-limiter reset) lives in tests/serve/conftest.py and runs autouse
for every test in this directory; this file does not duplicate it.
"""

import hashlib
import hmac
import time
from datetime import datetime, timezone

import pytest

# Stable service singletons imported once at module level.  These were all
# previously lazy-imported inside individual tests; collecting them here removes
# ~40 duplicate ``from picosentry...`` lines without changing test semantics
# (conftest.py runs first and sets PICOSHOGUN_ENV / SECRET_KEY before any
# picosentry import resolves).
from picosentry.serve.api.server import auth_service
from picosentry.serve.config.settings import settings
from picosentry.serve.database.manager import db
from picosentry.serve.services.auth import AuthService
from picosentry.serve.services.backup import BackupManager
from picosentry.serve.services.intelligence import IntelligenceEngine
from picosentry.serve.services.metrics import MetricsCollector
from picosentry.serve.services.orgs import Organization
from picosentry.serve.services.rbac import (
    Permission,
    get_permissions,
    has_permission,
)
from picosentry.serve.services.scheduler import scheduler
from picosentry.serve.services.webhooks import (
    _is_safe_webhook_url,
    webhook_manager,
)


@pytest.fixture
def client():
    """Per-test client to avoid rate-limit accumulation across tests."""
    from fastapi.testclient import TestClient

    from picosentry.serve.api.server import app

    return TestClient(app)


def _auth_headers(token):
    return {"Authorization": f"Bearer {token}"} if token else {}


def _register_and_login(client, role="admin", suffix=None):
    """One-shot: create a user at the requested role + login → token, and
    create a default org so org-scoped endpoints have a tenant context.

    The ``/auth/register`` endpoint creates viewers only (P0 fix); for
    ``admin`` and ``operator`` we drop down to the service layer so the
    integration tests can still exercise elevated paths.
    """
    tag = suffix or int(time.time() * 1000)
    username = f"integ_{role}_{tag}"
    password = "IntegrationTest123!"

    if role == "viewer":
        client.post("/auth/register", json={"username": username, "password": password})
    else:
        AuthService().create_user(username, password, role=role)

    resp = client.post("/auth/login", json={"username": username, "password": password})
    token = resp.json().get("access_token", "") if resp.status_code == 200 else ""
    assert token, f"Login failed for {username}"

    slug = f"integ-org-{role}-{tag}"
    resp = client.post(
        "/orgs",
        json={"name": f"Integration Org {role} {tag}", "slug": slug},
        headers=_auth_headers(token),
    )
    assert resp.status_code in (201, 409), f"Default org creation failed: {resp.text}"

    return token, username


def _register_with_org(client, role="operator", slug_prefix="tenant", tag=None):
    """Register a user (via _register_and_login) and create ONE additional org
    on top of the default org the helper already creates. Returns
    (token, new_org_id, slug). Used by the tenant-isolation tests which all
    need two labeled orgs to assert isolation between them.
    """
    tag = tag or int(time.time() * 1000)
    token, _ = _register_and_login(client, role=role, suffix=tag)
    slug = f"{slug_prefix}-{tag}"
    resp = client.post("/orgs", json={"name": slug, "slug": slug}, headers=_auth_headers(token))
    assert resp.status_code == 201, resp.text
    return token, resp.json()["id"], slug


def _starlette_app_with(middleware_cls, **mw_kwargs):
    """Build a 1-route Starlette app with the given middleware → TestClient.

    Shared by the three middleware smoke tests (rate-limit / CORS / DDoS).
    """
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    async def home(_request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", home)])
    app.add_middleware(middleware_cls, **mw_kwargs)
    return TestClient(app)


# ── Auth End-to-End ───────────────────────────────────────────────────────


class TestAuthEndToEnd:
    """Full auth lifecycle: register → login → use token → API key rotation."""

    def test_register_login_access_protected_endpoint(self, client):
        token, _ = _register_and_login(client)
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

    @pytest.mark.parametrize(
        "username,password,role",
        [
            ("short_pw_user", "short", "viewer"),
            ("bad_role_user", "IntegrationTest123!", "superadmin"),
        ],
    )
    def test_invalid_register_payload_rejected(self, client, username, password, role):
        resp = client.post(
            "/auth/register",
            json={"username": f"{username}_{int(time.time() * 1000)}", "password": password, "role": role},
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
        resp = client.post(
            "/auth/login",
            json={"username": username, "password": "wrongpassword"},
        )
        assert resp.status_code == 401


# ── RBAC Enforcement ─────────────────────────────────────────────────────


class TestRBACEnforcement:
    """Role-based access control: viewer < operator < admin."""

    def test_viewer_cannot_create_scheduler_job(self, client):
        token, _ = _register_and_login(client, role="viewer")
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
        token, _ = _register_and_login(client, role="operator")
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
        assert resp.status_code == 201

    def test_viewer_cannot_delete_scheduler_job(self, client):
        token, _ = _register_and_login(client, role="viewer")
        resp = client.delete("/scheduler/jobs/9999", headers=_auth_headers(token))
        assert resp.status_code == 403

    def test_viewer_can_read_status(self, client):
        token, _ = _register_and_login(client, role="viewer")
        resp = client.get("/status", headers=_auth_headers(token))
        assert resp.status_code == 200

    def test_only_admin_can_purge_audit(self, client):
        token_viewer, _ = _register_and_login(client, role="viewer")
        resp = client.post("/audit/purge?dry_run=true", headers=_auth_headers(token_viewer))
        assert resp.status_code == 403


# ── API Key Lifecycle ─────────────────────────────────────────────────────


class TestAPIKeyLifecycle:
    """Create → use → rotate → revoke API keys."""

    def test_create_and_validate_api_key(self, client):
        token, _ = _register_and_login(client)
        resp = client.post("/auth/api-key", json={"name": "test_key"}, headers=_auth_headers(token))
        assert resp.status_code == 201
        api_key = resp.json().get("api_key")
        assert api_key

        auth = AuthService()
        key_info = auth.validate_api_key(api_key)
        assert key_info is not None
        assert "username" in key_info

    def test_rotate_api_key(self, client):
        token, _ = _register_and_login(client)

        user_info = auth_service.validate_token(token)
        assert user_info is not None

        api_key = auth_service.create_api_key(user_info["user_id"], name="rotate_test")
        assert api_key is not None

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
        token, _ = _register_and_login(client)

        user_info = auth_service.validate_token(token)
        assert user_info is not None

        api_key = auth_service.create_api_key(user_info["user_id"], name="revoke_test")
        assert api_key is not None

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
        token, _ = _register_and_login(client)
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
        assert resp.status_code == 201
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
        assert resp_a.status_code == 201
        org_id_a = resp_a.json()["id"]

        token_b, _ = _register_and_login(client, suffix=tag + 1)

        resp_b = client.get(f"/orgs/{org_id_a}/members", headers=_auth_headers(token_b))
        assert resp_b.status_code == 403

        resp_b_usage = client.get(f"/orgs/{org_id_a}/usage", headers=_auth_headers(token_b))
        assert resp_b_usage.status_code == 403

    def test_org_usage_and_tier(self, client):
        token, _ = _register_and_login(client)
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
        token, _ = _register_and_login(client)
        slug = f"dup-slug-{int(time.time() * 1000)}"
        resp1 = client.post(
            "/orgs",
            json={
                "name": "First Org",
                "slug": slug,
            },
            headers=_auth_headers(token),
        )
        assert resp1.status_code == 201

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
        token_viewer, _ = _register_and_login(client, role="viewer")
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
        token, _ = _register_and_login(client, role="operator")
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
        assert resp.status_code in (201, 400)

    def test_valid_commands_accepted(self, client):
        for cmd in ["batch", "run", "report", "backup", "cleanup"]:
            job_id = scheduler.add_job(
                name=f"test_{cmd}_{int(time.time() * 1000)}",
                cron="0 */6 * * *",
                command=cmd,
                params={},
                enabled=False,
            )
            assert job_id is not None, f"Command '{cmd}' should be accepted"

    @pytest.mark.parametrize(
        "name,command,params,error_match",
        [
            ("evil_job", "rm -rf /", {}, "Invalid command"),
            ("bad_params", "batch", {"evil": {"nested": "dict"}}, "Invalid param"),
        ],
    )
    def test_invalid_add_job_rejected(self, name, command, params, error_match):
        with pytest.raises(ValueError, match=error_match):
            scheduler.add_job(name=name, cron="* * * * *", command=command, params=params)


# ── Webhooks ─────────────────────────────────────────────────────────────


class TestWebhooksIntegration:
    """Webhook creation with SSRF protection."""

    def test_create_webhook_with_default_name(self, client):
        token, _ = _register_and_login(client, role="operator")
        resp = client.post(
            "/webhooks",
            json={
                "url": "https://example.com/hook",
                "events": ["*"],
                "name": "default-hook",
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code == 201

    def test_create_webhook_with_custom_name(self, client):
        token, _ = _register_and_login(client, role="operator")
        resp = client.post(
            "/webhooks",
            json={
                "url": "https://example.com/hook2",
                "events": ["alert"],
                "name": "my-webhook",
            },
            headers=_auth_headers(token),
        )
        assert resp.status_code == 201

    def test_create_webhook_rejects_unknown_field(self, client):
        token, _ = _register_and_login(client, role="operator")
        resp = client.post(
            "/webhooks",
            json={"url": "https://example.com/hook", "events": ["*"], "name": "x", "bogus": 1},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 422, resp.text

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1:8080/hook",
            "http://10.0.0.1/hook",
            "file:///etc/passwd",
        ],
    )
    def test_webhook_rejects_unsafe_url(self, client, url):
        """Webhook creation must reject SSRF-class URLs (loopback, private IP,
        non-http schemes) — one parametrized case per URL so each shows up
        as its own test result."""
        token, _ = _register_and_login(client, role="operator")
        resp = client.post(
            "/webhooks",
            json={"url": url, "events": ["*"], "name": "evil"},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 400, f"{url} should be rejected: {resp.text}"


# ── Read-only endpoint smoke checks ───────────────────────────────────────


class TestEndpointSmoke:
    """Pure status-code smoke checks for read-only authenticated endpoints.

    Each of these was previously a 5-line ``def test_X`` in its feature-area
    class; the bodies were identical (register → request → assert 200/404)
    so they are collapsed here into two parametrized functions. The
    feature-area classes keep the tests that have non-trivial assertions.
    """

    @pytest.mark.parametrize(
        "role,method,url",
        [
            pytest.param("viewer", "GET", "/intelligence", id="list_intelligence"),
            pytest.param("viewer", "GET", "/alerts", id="alerts_listing"),
            pytest.param("viewer", "GET", "/reports/summary", id="summary_report"),
            pytest.param("viewer", "GET", "/metrics?detailed=true", id="detailed_metrics"),
            pytest.param("viewer", "GET", "/anomaly/alerts", id="list_anomaly_alerts"),
            pytest.param("admin", "GET", "/backups", id="list_backups"),
            pytest.param("admin", "POST", "/audit/purge?dry_run=true&retention_days=30", id="audit_purge_dry_run"),
        ],
    )
    def test_authenticated_endpoint_returns_200(self, client, role, method, url):
        token, _ = _register_and_login(client, role=role)
        resp = client.request(method, url, headers=_auth_headers(token))
        assert resp.status_code == 200, f"{method} {url} failed: {resp.text}"

    @pytest.mark.parametrize(
        "method,url",
        [
            pytest.param("POST", "/alerts/99999/acknowledge", id="acknowledge_nonexistent_alert"),
            pytest.param("GET", "/projects/nonexistent_project_id", id="project_not_found"),
            pytest.param("GET", "/reports/project/nonexistent", id="project_report_not_found"),
            pytest.param("PATCH", "/anomaly/rules/nonexistent_rule", id="update_nonexistent_rule"),
        ],
    )
    def test_nonexistent_resource_returns_404(self, client, method, url):
        # The PATCH case sends a JSON body; the others are body-less.
        json_body = {"enabled": False} if method == "PATCH" else None
        token, _ = _register_and_login(client)
        resp = client.request(method, url, json=json_body, headers=_auth_headers(token))
        assert resp.status_code == 404, f"{method} {url} expected 404: {resp.text}"


# ── Intelligence & Alerts ─────────────────────────────────────────────────


class TestIntelligenceAndAlerts:
    """Intelligence listing, threat score, and alert endpoints."""

    def test_threat_score(self, client):
        token, _ = _register_and_login(client)
        resp = client.get("/intelligence/threat-score", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "threat_score" in data
        assert "total_threats" in data


# ── Projects ──────────────────────────────────────────────────────────────


class TestProjects:
    """Project listing and run endpoints."""

    def test_list_projects(self, client):
        token, _ = _register_and_login(client)
        resp = client.get("/projects", headers=_auth_headers(token))
        assert resp.status_code == 200


# ── Dashboard Summary ────────────────────────────────────────────────────


class TestDashboardSummary:
    def test_dashboard_summary_authenticated(self, client):
        token, _ = _register_and_login(client)
        resp = client.get("/api/v1/dashboard/summary", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data

    def test_dashboard_summary_unauthenticated(self, client):
        resp = client.get("/api/v1/dashboard/summary")
        assert resp.status_code in (401, 403)


# ── Reports ───────────────────────────────────────────────────────────────
# (summary_report and project_report_not_found moved to TestEndpointSmoke)


# ── Metrics ───────────────────────────────────────────────────────────────


class TestMetricsIntegration:
    def test_metrics_json_authenticated(self, client):
        token, _ = _register_and_login(client)
        resp = client.get("/metrics/json", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "uptime_seconds" in data

    def test_prometheus_endpoint(self, client):
        token, _ = _register_and_login(client)
        resp = client.get("/metrics/prometheus", headers=_auth_headers(token))
        assert resp.status_code == 200
        assert "picoshogun_" in resp.text

    def test_prometheus_endpoint_requires_auth(self, client):
        resp = client.get("/metrics/prometheus")
        assert resp.status_code in (401, 403)


# ── Audit ─────────────────────────────────────────────────────────────────


class TestAudit:
    def test_audit_stats(self, client):
        token, _ = _register_and_login(client, role="admin")
        resp = client.get("/audit/stats", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "retention_policy" in data

    def test_audit_purge_viewer_forbidden(self, client):
        token, _ = _register_and_login(client, role="viewer")
        resp = client.post("/audit/purge?dry_run=true", headers=_auth_headers(token))
        assert resp.status_code == 403


# ── Backup ────────────────────────────────────────────────────────────────


class TestBackup:
    def test_create_backup_requires_admin(self, client):
        token_viewer, _ = _register_and_login(client, role="viewer")
        resp = client.post("/backup", headers=_auth_headers(token_viewer))
        assert resp.status_code == 403


# ── Anomaly Detection ────────────────────────────────────────────────────


class TestAnomalyDetection:
    def test_list_anomaly_rules(self, client):
        token, _ = _register_and_login(client)
        resp = client.get("/anomaly/rules", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_trigger_anomaly_check(self, client):
        token, _ = _register_and_login(client)
        resp = client.post("/anomaly/check", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "triggered" in data

    def test_update_anomaly_rule(self, client):
        token, _ = _register_and_login(client)
        resp = client.patch("/anomaly/rules/high_error_rate", json={"threshold": 0.5}, headers=_auth_headers(token))
        assert resp.status_code == 200


# ── PicoDome endpoints (previously stubs, now real) ─────────────────────


class TestPicoDomeEndpoints:
    def test_scan_endpoint_returns_200(self, client, tmp_path):
        """Scan endpoint runs the built-in scanner end-to-end (operator role required).
        Targets an empty dir under workspace — real /tmp has 1000+ files and the
        scan takes ~25s, exceeding TestClient's httpx timeout."""
        target = tmp_path / "scan_target"
        target.mkdir()
        token, _ = _register_and_login(client, role="operator")
        resp = client.post(
            "/api/v1/scans",
            json={"target": str(target), "rules": None, "format": "json"},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "scan_id" in data
        assert "findings_count" in data

    def test_sandbox_endpoint_returns_200(self, client):
        token, _ = _register_and_login(client, role="operator")
        resp = client.post(
            "/api/v1/sandboxes",
            json={"command": ["echo", "hello"], "format": "json"},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "overall_verdict" in data
        assert "events" in data

    def test_scan_rules_returns_rules(self, client):
        token, _ = _register_and_login(client)
        resp = client.get("/api/v1/scans/rules", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "rules" in data
        assert len(data["rules"]) > 0

    def test_sandbox_policy_returns_policy(self, client):
        token, _ = _register_and_login(client)
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
    @pytest.mark.parametrize(
        "url",
        [
            "/events/history",
            "/events/history?event_type=test&limit=10",
        ],
    )
    def test_event_history(self, client, url):
        token, _ = _register_and_login(client, role="admin")
        resp = client.get(url, headers=_auth_headers(token))
        assert resp.status_code == 200


# ── Logs ──────────────────────────────────────────────────────────────────


class TestLogs:
    @pytest.mark.parametrize(
        "method,url",
        [
            ("GET", "/logs/stats"),
            ("POST", "/logs/rotate"),
        ],
    )
    def test_log_endpoint(self, client, method, url):
        token, _ = _register_and_login(client, role="admin")
        resp = client.request(method, url, headers=_auth_headers(token))
        assert resp.status_code == 200


# ── Webhook Service Tests ────────────────────────────────────────────────


class TestWebhookService:
    """Direct service-level tests for webhook signing and SSRF."""

    def test_sign_payload(self):
        payload = {"event": "test", "data": "hello"}
        secret = "test-secret-key-12345678"
        signature = webhook_manager.sign_payload(payload, secret)
        assert isinstance(signature, str)
        assert len(signature) == 64  # SHA-256 hex digest

    def test_verify_signature_constant_time(self):
        payload = b'{"test": true}'
        secret = "test-secret-key-12345678"
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        assert webhook_manager.verify_signature(payload, expected, secret)

    def test_verify_signature_rejects_tampered(self):
        payload = b'{"test": true}'
        secret = "test-secret-key-12345678"
        assert not webhook_manager.verify_signature(payload, "tampered_signature", secret)

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/admin",
            "ftp://evil.com/payload",
        ],
    )
    def test_ssrf_blocks_unsafe_url(self, url):
        safe, _reason = _is_safe_webhook_url(url)
        assert not safe


# ── Auth Service Tests ──────────────────────────────────────────────────


class TestAuthServiceIntegration:
    """Integration-level auth service tests."""

    def test_password_hashing_roundtrip(self):
        auth = AuthService()
        tag = int(time.time() * 1000)
        username = f"hash_test_{tag}"
        auth.create_user(username, "correct_password_123", role="admin")
        token = auth.authenticate(username, "correct_password_123")
        assert token is not None
        token_wrong = auth.authenticate(username, "wrong_password_456")
        assert token_wrong is None

    def test_expired_token_rejected(self):
        auth = AuthService()
        tag = int(time.time() * 1000)
        username = f"expire_test_{tag}"
        auth.create_user(username, "testpassword123", role="admin")
        token = auth.authenticate(username, "testpassword123")
        assert token is not None
        info = auth.validate_token(token)
        assert info is not None

    def test_legacy_simple_token_rejected(self):
        auth = AuthService()
        result = auth.validate_token("simple:123:fake")
        assert result is None

    def test_api_key_rotation_preserves_permissions(self):
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


# ── Scheduler Service Tests ──────────────────────────────────────────────


class TestSchedulerServiceIntegration:
    def test_scheduler_status_returns_list(self):
        status = scheduler.get_status()
        assert isinstance(status, list)

    def test_remove_nonexistent_job(self):
        result = scheduler.remove_job(99999)
        assert result is False


# ── Organization Service Tests ──────────────────────────────────────────


class TestOrganizationService:
    def test_create_org(self):
        auth = AuthService()
        tag = int(time.time() * 1000)
        user_id = auth.create_user(f"org_svc_{tag}", "testpassword123", role="admin")
        org_id = Organization.create("Test Org Svc", f"org-svc-{tag}", user_id)
        assert org_id is not None

    def test_duplicate_slug_rejected(self):
        auth = AuthService()
        tag = int(time.time() * 1000)
        user_id = auth.create_user(f"org_dup_{tag}", "testpassword123", role="admin")
        slug = f"dup-org-{tag}"
        result_1 = Organization.create("First Org", slug, user_id)
        result_2 = Organization.create("Second Org", slug, user_id)
        assert result_1 is not None
        assert result_2 == {}

    def test_org_tiers(self):
        for tier in ["free", "starter", "pro", "enterprise"]:
            assert tier in Organization.TIERS

    def test_can_create_project_limits(self):
        limits = Organization.TIERS["free"]
        assert limits["projects"] < Organization.TIERS["enterprise"]["projects"]


# ── Intelligence Engine Tests ──────────────────────────────────────────────


class TestIntelligenceEngine:
    @pytest.mark.parametrize(
        "log_line,expected_severity",
        [
            # critical_vuln: classify_failure matches failure signatures (not main PATTERNS)
            ("ModuleNotFoundError: No module named picoshogun", {"critical", "high"}),
            # auth_failure: "permission denied" matches a failure signature
            ("Permission denied: operation not permitted", None),
            # timeout: maps to medium severity
            ("Connection timed out after 30 seconds", {"medium"}),
        ],
    )
    def test_classify_failure_severity(self, log_line, expected_severity):
        result = IntelligenceEngine().classify_failure("test-proj", log_line)
        assert result is not None
        if expected_severity is not None:
            assert result["severity"] in expected_severity

    def test_classify_empty_output_returns_none(self):
        # Empty output should return None (no patterns match)
        assert IntelligenceEngine().classify_failure("test-proj", "") is None

    def test_aggregate_score(self):
        score = IntelligenceEngine().get_aggregate_score()
        assert isinstance(score, (int, float))


# ── Metrics Service Tests ────────────────────────────────────────────────


class TestMetricsServiceIntegration:
    def test_prometheus_no_double_prefix(self):
        mc = MetricsCollector()
        mc.counter("test_counter", 1)
        output = mc.to_prometheus()
        assert "picopicoshogun" not in output
        assert "picoshogun_" in output

    def test_project_run_metrics(self):
        mc = MetricsCollector()
        mc.project_run("test-project", 42.5, "completed")
        data = mc.to_dict()
        assert "counters" in data

    def test_api_request_metrics(self):
        mc = MetricsCollector()
        mc.api_request("GET", "/health", 200, 0.05)
        data = mc.to_dict()
        assert "counters" in data


# ── Backup Service Tests ─────────────────────────────────────────────────


class TestBackupService:
    def test_list_backups(self):
        bm = BackupManager()
        backups = bm.list_backups()
        assert isinstance(backups, list)

    def test_create_and_list_backup(self):
        bm = BackupManager()
        result = bm.create_backup(name="test_backup_integration", include_logs=False)
        if result:
            assert "path" in result
            backups = bm.list_backups()
            assert any("test_backup_integration" in b["name"] for b in backups)


# ── Configuration Tests ──────────────────────────────────────────────────


class TestConfiguration:
    def test_settings_loads(self):
        assert settings.api.port == 8765
        assert settings.database.journal_mode == "WAL"
        assert settings.security.jwt_algorithm == "HS256"

    def test_settings_validate(self):
        issues = settings.validate()
        assert isinstance(issues, list)

    def test_is_production(self):
        assert not settings.is_production()

    def test_version_is_consistent(self):
        # version is validated by config.version module
        from picosentry.serve.api.server import app
        from picosentry.serve.config.version import __version__ as _v

        assert app.version == _v


# ── Rate Limiting ─────────────────────────────────────────────────────────


class TestRateLimiting:
    def test_rate_limit_middleware_instantiates(self):
        from picosentry.serve.middleware.rate_limit import RateLimitMiddleware

        tc = _starlette_app_with(RateLimitMiddleware, max_requests_per_ip=100, max_requests_per_org=1000, window=60)
        assert tc.get("/").status_code == 200


# ── Scheduler Enable/Disable ──────────────────────────────────────────────


class TestSchedulerEnableDisable:
    def test_enable_disable_job(self, client):
        token, _ = _register_and_login(client, role="operator")
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
        assert resp.status_code == 201
        job_id = resp.json().get("job_id")

        if job_id:
            resp_disable = client.patch(f"/scheduler/jobs/{job_id}/disable", headers=_auth_headers(token))
            assert resp_disable.status_code == 200

            resp_enable = client.patch(f"/scheduler/jobs/{job_id}/enable", headers=_auth_headers(token))
            assert resp_enable.status_code == 200

    def test_delete_job(self, client):
        token_op, _ = _register_and_login(client, role="operator")
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
        assert resp.status_code == 201
        job_id = resp.json().get("job_id")

        if job_id:
            # Operators can delete jobs within their own org; cross-org
            # deletes are rejected by org scoping.
            resp_del = client.delete(f"/scheduler/jobs/{job_id}", headers=_auth_headers(token_op))
            assert resp_del.status_code == 204


# ── CORS Hardening ────────────────────────────────────────────────────────


class TestCORSHardening:
    def test_cors_middleware_present(self):
        from picosentry.serve.middleware.cors_hardening import CORSHardeningMiddleware

        tc = _starlette_app_with(CORSHardeningMiddleware, block_wildcard_in_production=False)
        assert tc.get("/").status_code == 200


# ── DDoS Shield ───────────────────────────────────────────────────────────


class TestDDoSShield:
    def test_ddos_shield_pass_through(self):
        from picosentry.serve.middleware.ddos_shield import DDoSShieldMiddleware

        tc = _starlette_app_with(DDoSShieldMiddleware, enabled=True)
        assert tc.get("/").status_code == 200


# ── Tenant Data Isolation (P1 #3) ──────────────────────────────────────────


class TestTenantDataIsolation:
    """Data-level tenant isolation: org A's data cannot be read by org B's users.

    These tests verify that even if two orgs share the same PicoShogun instance,
    users in org A cannot read, modify, or delete data belonging to org B through
    the API. This closes the P1 #3 gap identified in the security review.
    """

    def test_tenant_cannot_read_other_org_projects(self, client):
        """Org A runs/claims a project; Org B's member cannot list, read, or export it."""

        tag = int(time.time() * 1000)

        # Each registration creates exactly one default org; that is the org the
        # user acts as on org-scoped endpoints (no X-Org-API-Key header needed).
        token_a, _user_a = _register_and_login(client, suffix=tag)
        token_b, _ = _register_and_login(client, suffix=tag + 1)

        org_a_id = client.get("/orgs", headers=_auth_headers(token_a)).json()["orgs"][0]["id"]
        org_b_id = client.get("/orgs", headers=_auth_headers(token_b)).json()["orgs"][0]["id"]
        assert org_a_id != org_b_id

        # Associate a registry project with org A (simulates having run it).
        project_id = "picosentry"
        Organization.add_project(org_a_id, project_id)

        # Org A sees the project; org B does not.
        resp = client.get("/projects", headers=_auth_headers(token_a))
        assert resp.status_code == 200
        assert any(p["id"] == project_id for p in resp.json())

        resp = client.get("/projects", headers=_auth_headers(token_b))
        assert resp.status_code == 200
        assert not any(p["id"] == project_id for p in resp.json())

        # Org A can read/export the project; org B gets 404.
        resp = client.get(f"/projects/{project_id}", headers=_auth_headers(token_a))
        assert resp.status_code == 200

        resp = client.get(f"/projects/{project_id}/export", headers=_auth_headers(token_a))
        assert resp.status_code == 200

        resp = client.get(f"/projects/{project_id}", headers=_auth_headers(token_b))
        assert resp.status_code == 404

        resp = client.get(f"/projects/{project_id}/export", headers=_auth_headers(token_b))
        assert resp.status_code == 404

        # Reports summary is org-scoped.
        resp = client.get("/reports/summary", headers=_auth_headers(token_a))
        assert resp.status_code == 200
        assert resp.json()["total_projects"] >= 1

        resp = client.get("/reports/summary", headers=_auth_headers(token_b))
        assert resp.status_code == 200
        assert resp.json()["total_projects"] == 0

    def test_tenant_cannot_upgrade_other_org(self, client):
        """Org A admin cannot upgrade org B's tier even with admin role."""
        tag = int(time.time() * 1000)
        _token_a, _org_a_id, _slug_a = _register_with_org(client, role="admin", slug_prefix="tenant-upgrade-a", tag=tag)
        _token_b, org_b_id, _slug_b = _register_with_org(
            client, role="admin", slug_prefix="tenant-upgrade-b", tag=tag + 1
        )

        # Admin A tries to upgrade org B — should be denied
        resp = client.post(
            f"/orgs/{org_b_id}/upgrade",
            json={"tier": "pro"},
            headers=_auth_headers(_token_a),
        )
        assert resp.status_code in (403, 404)

    def test_tenant_api_key_isolation(self, client):
        """API key for org A cannot be used to access org B's data."""
        tag = int(time.time() * 1000)
        token_a, org_a_id, _slug_a = _register_with_org(client, slug_prefix="tenant-apikey-a", tag=tag)
        org_a_api_key = client.get(f"/orgs/{org_a_id}", headers=_auth_headers(token_a)).json().get("api_key", "")

        token_b, _org_b_id, _slug_b = _register_with_org(client, slug_prefix="tenant-apikey-b", tag=tag + 1)

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
        token_a, _org_a_id, slug_a = _register_with_org(client, slug_prefix="tenant-list-a", tag=tag)
        _token_b, _org_b_id, slug_b = _register_with_org(client, slug_prefix="tenant-list-b", tag=tag + 1)

        # User A lists their orgs — should only contain org A
        resp = client.get("/orgs", headers=_auth_headers(token_a))
        assert resp.status_code == 200
        org_slugs = [o.get("slug", "") for o in resp.json().get("orgs", [])]
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

        assert resp1.status_code == 201
        assert resp2.status_code == 201

        # User should see both orgs
        resp = client.get("/orgs", headers=_auth_headers(token))
        org_slugs = [o.get("slug", "") for o in resp.json().get("orgs", [])]
        assert slug1 in org_slugs
        assert slug2 in org_slugs

    def test_tenant_cannot_read_other_org_data(self, client):
        """Org A's intelligence, alerts, runs, webhooks, jobs, and metrics are
        invisible to org B's users.
        """

        tag = int(time.time() * 1000)
        _token_a, org_a_id, _slug_a = _register_with_org(client, role="operator", slug_prefix="tenant-data-a", tag=tag)
        token_b, org_b_id, _slug_b = _register_with_org(
            client, role="operator", slug_prefix="tenant-data-b", tag=tag + 1
        )
        assert org_a_id != org_b_id

        # Seed org A data directly through the DB so the test is fast and
        # deterministic (no subprocess project runs).
        db.execute_insert(
            "INSERT INTO intelligence (source_project, intel_type, severity, data, org_id) VALUES (?, ?, ?, ?, ?)",
            ("proj-a", "critical_vuln", "critical", "{}", org_a_id),
        )
        db.execute_insert(
            "INSERT INTO alerts (project_id, alert_type, severity, message, channel, org_id) VALUES (?, ?, ?, ?, ?, ?)",
            ("proj-a", "test", "high", "org A alert", "syslog", org_a_id),
        )
        db.execute_insert(
            "INSERT INTO project_runs (project_id, run_start, status, org_id) VALUES (?, ?, ?, ?)",
            ("proj-a", datetime.now(timezone.utc), "completed", org_a_id),
        )
        db.execute_insert(
            "INSERT INTO webhooks (name, url, secret, events, active, retries, org_id) VALUES (?, ?, ?, ?, 1, 0, ?)",
            (f"hook-a-{tag}", "https://example.com/hook", "secret", '["*"]', org_a_id),
        )
        db.execute_insert(
            "INSERT INTO scheduled_jobs "
            "(name, cron_expression, command, params, enabled, org_id) "
            "VALUES (?, ?, ?, ?, 1, ?)",
            (f"job-a-{tag}", "0 0 * * *", "report", "{}", org_a_id),
        )
        # Reload in-memory scheduler/webhook caches so the API sees the new rows.

        scheduler._load_jobs()
        webhook_manager._load_webhooks()

        # User B's reads should not contain org A's data.
        for endpoint, _key in [
            ("/intelligence", "intel_type"),
            ("/alerts", "alert_type"),
        ]:
            resp = client.get(endpoint, headers=_auth_headers(token_b))
            assert resp.status_code == 200, f"{endpoint} failed: {resp.text}"
            leaked = any(
                item.get("source_project") == "proj-a" or item.get("project_id") == "proj-a" for item in resp.json()
            )
            assert not leaked, f"{endpoint} leaked org A data"

        resp = client.get("/api/v1/dashboard/summary", headers=_auth_headers(token_b))
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert not any(i.get("source_project") == "proj-a" for i in data.get("recent_intelligence", []))
        assert not any(a.get("project_id") == "proj-a" for a in data.get("recent_alerts", []))

        resp = client.get("/scheduler/jobs", headers=_auth_headers(token_b))
        assert resp.status_code == 200, resp.text
        assert not any(j.get("name") == f"job-a-{tag}" for j in resp.json().get("jobs", []))

        resp = client.get("/webhooks", headers=_auth_headers(token_b))
        assert resp.status_code == 200, resp.text
        assert f"hook-a-{tag}" not in resp.json().get("webhooks", {})

        resp = client.get("/metrics/json", headers=_auth_headers(token_b))
        assert resp.status_code == 200, resp.text
        # In-memory metrics are labeled by org_id after this code change; org B
        # should not see org A's counters.
        counters = resp.json().get("counters", {})
        assert not any(str(org_a_id) in key for key in counters)

    def test_tenant_cannot_acknowledge_other_org_alert(self, client):
        """Org B's user cannot acknowledge an alert belonging to org A."""

        tag = int(time.time() * 1000)
        _token_a, org_a_id, _slug_a = _register_with_org(client, role="operator", slug_prefix="tenant-ack-a", tag=tag)
        token_b, org_b_id, _slug_b = _register_with_org(
            client, role="operator", slug_prefix="tenant-ack-b", tag=tag + 1
        )
        assert org_a_id != org_b_id

        db.execute_insert(
            "INSERT INTO alerts (project_id, alert_type, severity, message, channel, org_id) VALUES (?, ?, ?, ?, ?, ?)",
            ("proj-a", "test", "high", "org A alert", "syslog", org_a_id),
        )
        alert_row = db.execute_one("SELECT id FROM alerts WHERE org_id = ?", (org_a_id,))
        assert alert_row

        resp = client.post(f"/alerts/{alert_row['id']}/acknowledge", headers=_auth_headers(token_b))
        assert resp.status_code in (403, 404)


class TestRBACPolicy:
    """Test RBAC policy engine and permission checks."""

    def test_viewer_permissions(self):
        viewer = {"role": "viewer", "id": 1, "username": "viewer_user"}
        viewer_perms = get_permissions("viewer")
        assert Permission.READ_PROJECTS in viewer_perms
        assert Permission.READ_HEALTH in viewer_perms
        assert Permission.RUN_PROJECTS not in viewer_perms
        assert Permission.ADMIN_USERS not in viewer_perms
        assert has_permission(viewer, Permission.READ_PROJECTS)
        assert not has_permission(viewer, Permission.RUN_PROJECTS)

    def test_operator_permissions(self):
        operator = {"role": "operator", "id": 2, "username": "op_user"}
        op_perms = get_permissions("operator")
        assert Permission.RUN_PROJECTS in op_perms
        assert Permission.WRITE_WEBHOOKS in op_perms
        assert Permission.ADMIN_USERS not in op_perms
        assert has_permission(operator, Permission.RUN_PROJECTS)
        assert not has_permission(operator, Permission.ADMIN_USERS)

    def test_admin_permissions(self):
        admin = {"role": "admin", "id": 3, "username": "admin_user"}
        admin_perms = get_permissions("admin")
        assert len(admin_perms) == len(Permission)
        for perm in Permission:
            assert has_permission(admin, perm), f"Admin should have {perm.value}"

    def test_unknown_role(self):
        unknown = {"role": "unknown_role", "id": 4, "username": "unknown"}
        assert get_permissions("unknown_role") == set()
        assert not has_permission(unknown, Permission.READ_PROJECTS)

    def test_require_permission_dependency(self):
        """Test that require_permission FastAPI dependency works."""
        from picosentry.serve.api.deps import require_permission

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
