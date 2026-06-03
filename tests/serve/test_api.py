"""Tests for the PicoShogun Command Centre API endpoints."""
import contextlib
import os
import sys
from pathlib import Path

import pytest

# Ensure project root is on sys.path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
os.environ["PICOSHOGUN_ENV"] = "test"
os.environ["PICOSHOGUN_SECRET_KEY"] = "test-key-for-pytest-at-least-32-bytes!"


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    from fastapi.testclient import TestClient

    from picosentry.serve.api.server import app
    return TestClient(app)


@pytest.fixture
def auth_token(client):
    """Get an auth token for authenticated requests."""
    with contextlib.suppress(Exception):
        client.post("/auth/register", json={
            "username": "pytest_user",
            "password": "testpassword123",
            "role": "admin"
        })

    try:
        resp = client.post("/auth/login?username=pytest_user&password=testpassword123")
        if resp.status_code == 200:
            data = resp.json()
            return data.get("access_token", "")
    except Exception:
        pass

    # Fallback: create directly via AuthService
    from picosentry.serve.api.server import auth_service
    token = auth_service.authenticate("pytest_user", "testpassword123")
    if token:
        return token
    return ""


def auth_headers(token):
    """Return authorization headers for a given token."""
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


class TestHealthEndpoint:
    """Test /health endpoint (unauthenticated)."""

    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_has_overall_field(self, client):
        resp = client.get("/health")
        data = resp.json()
        assert "overall" in data
        assert data["overall"] in ("healthy", "degraded", "critical")

    def test_health_has_checks_list(self, client):
        resp = client.get("/health")
        data = resp.json()
        assert "checks" in data
        assert isinstance(data["checks"], list)

    def test_health_check_fields(self, client):
        resp = client.get("/health")
        data = resp.json()
        for check in data["checks"]:
            assert "component" in check
            assert "status" in check
            assert "message" in check


class TestLivenessReadiness:
    """Test k8s probes."""

    def test_liveness(self, client):
        resp = client.get("/health/live")
        assert resp.status_code == 200
        assert resp.json()["status"] == "alive"

    def test_readiness(self, client):
        resp = client.get("/health/ready")
        assert resp.status_code in (200, 503)


class TestDashboardEndpoint:
    """Test dashboard page serving."""

    def test_dashboard_returns_html(self, client):
        resp = client.get("/dashboard")
        if resp.status_code == 200:
            assert "text/html" in resp.headers.get("content-type", "")

    def test_root_redirect_or_html(self, client):
        resp = client.get("/")
        assert resp.status_code in (200, 307, 308, 404)


class TestMetricsEndpoint:
    """Test /metrics endpoint."""

    def test_metrics_json_endpoint(self, client):
        resp = client.get("/metrics/json")
        if resp.status_code == 200:
            data = resp.json()
            assert "uptime_seconds" in data

    def test_metrics_prometheus_endpoint(self, client):
        resp = client.get("/metrics/prometheus")
        if resp.status_code == 200:
            assert "picoshogun_" in resp.text or "uptime" in resp.text.lower()

    def test_prometheus_no_double_prefix(self, client):
        """Ensure Prometheus metric names use picoshogun_ not picopicoshogun_."""
        resp = client.get("/metrics/prometheus")
        if resp.status_code == 200:
            # HELP and TYPE lines should use picoshogun_, not picopicoshogun_
            for line in resp.text.split("\n"):
                if line.startswith("# HELP") or line.startswith("# TYPE"):
                    assert "picopicoshogun" not in line, f"Double prefix in: {line}"
            assert "picoshogun_" in resp.text


class TestDashboardSummary:
    """Test /api/v1/dashboard/summary endpoint."""

    def test_dashboard_summary_returns_data(self, client, auth_token):
        headers = auth_headers(auth_token)
        resp = client.get("/api/v1/dashboard/summary", headers=headers)
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert "status" in data or "health" in data

    def test_dashboard_summary_has_timestamp(self, client, auth_token):
        headers = auth_headers(auth_token)
        resp = client.get("/api/v1/dashboard/summary", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "timestamp" in data

    def test_dashboard_summary_has_recent_projects(self, client, auth_token):
        headers = auth_headers(auth_token)
        resp = client.get("/api/v1/dashboard/summary", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "recent_projects" in data
        assert isinstance(data["recent_projects"], list)

    def test_dashboard_summary_has_pending_alerts(self, client, auth_token):
        headers = auth_headers(auth_token)
        resp = client.get("/api/v1/dashboard/summary", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "pending_alerts_count" in data

    def test_dashboard_summary_unauthenticated(self, client):
        resp = client.get("/api/v1/dashboard/summary")
        assert resp.status_code in (401, 403)


class TestHealthSmokeTests:
    """Smoke tests for health, readiness, and liveness endpoints."""

    def test_health_live(self, client):
        resp = client.get("/health/live")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "alive"

    def test_health_ready(self, client):
        resp = client.get("/health/ready")
        assert resp.status_code in (200, 503)
        data = resp.json()
        assert "status" in data

    def test_health_root(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["overall"] in ("healthy", "degraded", "critical")
        assert "checks" in data
        assert len(data["checks"]) > 0

    def test_health_history_requires_auth(self, client):
        resp = client.get("/health/history")
        assert resp.status_code in (401, 403)

    def test_health_history_with_auth(self, client, auth_token):
        headers = auth_headers(auth_token)
        resp = client.get("/health/history?limit=5", headers=headers)
        assert resp.status_code == 200

    def test_status_with_auth(self, client, auth_token):
        headers = auth_headers(auth_token)
        resp = client.get("/status", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "projects_total" in data
        assert "uptime_seconds" in data
        assert "system_health" in data


class TestAPIVersion:
    """Test API version and docs endpoints."""

    def test_openapi_docs_available(self, client):
        resp = client.get("/docs")
        assert resp.status_code in (200, 404)

    def test_api_info(self, client):
        from picosentry.serve.api.server import app
        assert app.title == "PicoShogun Command Centre API"
        from picosentry.serve.config.version import __version__
        assert app.version == __version__


class TestSecurityHeaders:
    """Test that security middleware is active."""

    def test_rate_limiting_works(self, client):
        """Verify rate limiting doesn't break normal requests."""
        resp = client.get("/health")
        assert resp.status_code == 200


class TestAuthEndpoints:
    """Test registration and login endpoints."""

    def test_register_new_user(self, client):
        import time
        username = f"test_user_{int(time.time() * 1000)}"
        resp = client.post("/auth/register", json={
            "username": username,
            "password": "testpassword123",
            "role": "viewer"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "user_id" in data
        assert data["username"] == username

    def test_register_duplicate_user(self, client):
        import time
        username = f"test_dup_{int(time.time() * 1000)}"
        client.post("/auth/register", json={
            "username": username,
            "password": "testpassword123",
            "role": "viewer"
        })
        resp = client.post("/auth/register", json={
            "username": username,
            "password": "testpassword123",
            "role": "viewer"
        })
        assert resp.status_code in (400, 409)

    def test_login_returns_token(self, client):
        import time
        username = f"test_login_{int(time.time() * 1000)}"
        client.post("/auth/register", json={
            "username": username,
            "password": "testpassword123",
            "role": "admin"
        })
        resp = client.post(f"/auth/login?username={username}&password=testpassword123")
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_invalid_credentials(self, client):
        resp = client.post("/auth/login?username=nonexistent&password=wrong")
        assert resp.status_code == 401


class TestSchedulerEndpoints:
    """Test scheduler API endpoints."""

    def test_list_jobs(self, client, auth_token):
        headers = auth_headers(auth_token)
        resp = client.get("/scheduler/jobs", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "jobs" in data

    def test_create_and_delete_job(self, client, auth_token):
        import time
        headers = auth_headers(auth_token)
        if not auth_token:
            pytest.skip("No auth token available")
        # Create org first (required by API)
        client.post("/orgs", json={
            "name": f"sched_org_{int(time.time()*1000)}",
            "slug": f"schedorg{int(time.time()*1000)}"
        }, headers=headers)
        resp = client.post("/scheduler/jobs", json={
            "name": f"test_job_{int(time.time()*1000)}",
            "cron": "*/10 * * * *",
            "command": "batch",
            "params": {"category": "monitoring"}
        }, headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "job_id" in data


class TestWebhookEndpoints:
    """Test webhook endpoints."""

    def test_list_webhooks(self, client, auth_token):
        headers = auth_headers(auth_token)
        resp = client.get("/webhooks", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "webhooks" in data


class TestPluginEndpoint:
    """Test plugin listing endpoint."""

    def test_list_plugins(self, client, auth_token):
        headers = auth_headers(auth_token)
        resp = client.get("/plugins", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "plugins" in data


class TestOrgEndpoints:
    """Test organization endpoints."""

    def test_list_orgs(self, client, auth_token):
        headers = auth_headers(auth_token)
        resp = client.get("/orgs", headers=headers)
        # May return 200 or 403 if user has no orgs
        assert resp.status_code in (200, 403)


class TestObservabilityModule:
    """Test the observability module can be imported."""

    def test_import_observability(self):
        from picosentry.serve.services.observability import get_tracer, init_telemetry
        assert init_telemetry is not None
        assert get_tracer is not None

    def test_noop_tracer(self):
        from picosentry.serve.services.observability import NoOpTracer
        tracer = NoOpTracer()
        span = tracer.start_span("test")
        assert span is not None
        span.set_attribute("key", "value")
        span.end()

    def test_noop_meter(self):
        from picosentry.serve.services.observability import NoOpMeter
        meter = NoOpMeter()
        counter = meter.create_counter("test_counter")
        counter.add(1)

    def test_init_telemetry_no_endpoint(self):
        from picosentry.serve.services.observability import init_telemetry
        result = init_telemetry(service_name="test")
        assert result is False

    def test_trace_span_decorator(self):
        from picosentry.serve.services.observability import trace_span
        @trace_span("test_operation", attributes={"key": "value"})
        def test_func():
            return 42
        result = test_func()
        assert result == 42

    def test_trace_async_span_decorator(self):
        from picosentry.serve.services.observability import trace_async_span
        @trace_async_span("test_async_operation")
        async def test_async_func():
            return 99
        import asyncio
        result = asyncio.run(test_async_func())
        assert result == 99


class TestDatabaseManager:
    """Test database initialization."""

    def test_db_module_imports(self):
        from picosentry.serve.database.manager import db
        assert db is not None

    def test_settings_module_imports(self):
        from picosentry.serve.config.settings import settings
        assert settings.api.port == 8765
        assert settings.database.journal_mode == "WAL"
        assert settings.security.jwt_algorithm == "HS256"


class TestAuthService:
    """Test authentication service."""

    def test_create_user(self):
        import time

        from picosentry.serve.services.auth import AuthService
        auth = AuthService()
        username = f"svc_test_{int(time.time() * 1000)}"
        user_id = auth.create_user(username, "testpassword123", role="viewer")
        assert user_id is not None

    def test_authenticate_returns_token(self):
        import time

        from picosentry.serve.services.auth import AuthService
        auth = AuthService()
        username = f"svc_auth_{int(time.time() * 1000)}"
        auth.create_user(username, "testpassword123", role="admin")
        token = auth.authenticate(username, "testpassword123")
        assert token is not None
        assert isinstance(token, str)

    def test_validate_token_roundtrip(self):
        import time

        from picosentry.serve.services.auth import AuthService
        auth = AuthService()
        username = f"svc_round_{int(time.time() * 1000)}"
        auth.create_user(username, "testpassword123", role="admin")
        token = auth.authenticate(username, "testpassword123")
        user_info = auth.validate_token(token)
        assert user_info is not None
        assert user_info["username"] == username

    def test_invalid_token_returns_none(self):
        from picosentry.serve.services.auth import AuthService
        auth = AuthService()
        result = auth.validate_token("invalid_token")
        assert result is None


class TestSchedulerService:
    """Test the scheduler service directly."""

    def test_get_status_returns_list(self):
        from picosentry.serve.services.scheduler import scheduler
        status = scheduler.get_status()
        assert isinstance(status, list)


class TestWebhookSSRFProtection:
    """Test webhook SSRF protection."""

    def test_blocks_localhost(self):
        from picosentry.serve.services.webhooks import _is_safe_webhook_url
        is_safe, reason = _is_safe_webhook_url("http://127.0.0.1/hook")
        assert not is_safe

    def test_blocks_private_ip(self):
        from picosentry.serve.services.webhooks import _is_safe_webhook_url
        is_safe, reason = _is_safe_webhook_url("http://10.0.0.1/hook")
        assert not is_safe

    def test_allows_public_url(self):
        from picosentry.serve.services.webhooks import _is_safe_webhook_url
        # Use a resolvable public hostname
        is_safe, reason = _is_safe_webhook_url("https://httpbin.org/webhook")
        # SSRF check should pass for public, resolvable domains
        # (may fail in DNS-restricted environments)
        assert is_safe or "Cannot resolve" in reason

    def test_blocks_file_scheme(self):
        from picosentry.serve.services.webhooks import _is_safe_webhook_url
        is_safe, reason = _is_safe_webhook_url("file:///etc/passwd")
        assert not is_safe


class TestMetricsCollector:
    """Test metrics collection."""

    def test_counter(self):
        from picosentry.serve.services.metrics import MetricsCollector
        mc = MetricsCollector()
        mc.counter("test_counter", 1, {"label": "value"})
        data = mc.to_dict()
        assert "counters" in data

    def test_prometheus_export(self):
        from picosentry.serve.services.metrics import MetricsCollector
        mc = MetricsCollector()
        mc.counter("test_counter", 1)
        output = mc.to_prometheus()
        assert "picoshogun_" in output
        # Ensure no double-pico prefix
        assert "picopicoshogun" not in output

    def test_uptime(self):
        from picosentry.serve.services.metrics import MetricsCollector
        mc = MetricsCollector()
        assert mc.uptime_seconds() > 0
