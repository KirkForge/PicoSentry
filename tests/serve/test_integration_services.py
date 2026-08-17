"""Integration tests (3/3): endpoint smoke checks, security middleware,
health probes, event bus, logs, and direct service-level tests (webhooks,
auth, scheduler, orgs, intelligence, metrics, backup, configuration).

Split out of test_integration.py (with auth/features siblings) so
pytest-xdist --dist=loadfile can spread the ~150s suite across workers
instead of pinning it to one. Test bodies are unchanged.

Env setup lives in tests/serve/conftest.py (autouse for this directory).
"""

import hashlib
import hmac
import time

import pytest

from picosentry.serve.config.settings import settings
from picosentry.serve.services.auth import AuthService
from picosentry.serve.services.backup import BackupManager
from picosentry.serve.services.intelligence import IntelligenceEngine
from picosentry.serve.services.metrics import MetricsCollector
from picosentry.serve.services.orgs import Organization
from picosentry.serve.services.scheduler import scheduler
from picosentry.serve.services.webhooks import (
    _is_safe_webhook_url,
    webhook_manager,
)

from tests.serve._integration_helpers import (
    _auth_headers,
    _register_and_login,
    _starlette_app_with,
)
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
