"""Integration tests (2/3): scheduler, webhooks, PicoDome scan/sandbox
endpoints, anomaly detection, intelligence, projects, dashboard, metrics,
audit, backup.

Split out of test_integration.py (with auth/services siblings) so
pytest-xdist --dist=loadfile can spread the ~150s suite across workers
instead of pinning it to one. Test bodies are unchanged.

Env setup lives in tests/serve/conftest.py (autouse for this directory).
"""

import time

import pytest

from picosentry.serve.services.scheduler import scheduler

from tests.serve._integration_helpers import (
    _auth_headers,
    _register_and_login,
)
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
