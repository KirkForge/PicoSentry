"""Integration tests (1/3): auth end-to-end, RBAC, API keys, org + tenant
data isolation.

Split out of test_integration.py (with features/services siblings) so
pytest-xdist --dist=loadfile can spread the ~150s suite across workers
instead of pinning it to one. Test bodies are unchanged.

Env setup (PICOSHOGUN_ENV, SECRET_KEY, per-worker DB path, rate-limiter
reset) lives in tests/serve/conftest.py and runs autouse for every test in
this directory.
"""

import time
from datetime import datetime, timezone

import pytest

from picosentry.serve.api.server import auth_service
from picosentry.serve.database.manager import db
from picosentry.serve.services.auth import AuthService
from picosentry.serve.services.orgs import Organization
from picosentry.serve.services.rbac import (
    Permission,
    get_permissions,
    has_permission,
)
from picosentry.serve.services.scheduler import scheduler
from picosentry.serve.services.webhooks import webhook_manager

from tests.serve._integration_helpers import (
    _auth_headers,
    _register_and_login,
    _register_with_org,
)
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
            "INSERT INTO webhooks (name, url, secret, events, active, retries, org_id) VALUES (?, ?, ?, ?, ?, 0, ?)",
            (f"hook-a-{tag}", "https://example.com/hook", "secret", '["*"]', True, org_a_id),
        )
        db.execute_insert(
            "INSERT INTO scheduled_jobs "
            "(name, cron_expression, command, params, enabled, org_id) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (f"job-a-{tag}", "0 0 * * *", "report", "{}", True, org_a_id),
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
