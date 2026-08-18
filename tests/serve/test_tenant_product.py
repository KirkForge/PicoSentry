"""WO5.0.0-032: tenant product completeness — tier quotas, member
management, org-switch header, offset pagination.

API-level (TestClient) plus a few direct service checks. No real subprocess:
the orchestrator run path is entered with a fake CompletedProcess via
monkeypatch (registry/PICO_CLI via monkeypatch.setitem so state restores).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from picosentry.serve.database.manager import db


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_headers():
    """Global-admin user with its own org (owner => org-level admin)."""
    from picosentry.serve.api.server import auth_service
    from picosentry.serve.services.orgs import Organization

    tag = uuid.uuid4().hex[:8]
    user_id = auth_service.create_user(f"tp-admin-{tag}", "testpassword123", role="admin")
    assert user_id
    token = auth_service.authenticate(f"tp-admin-{tag}", "testpassword123")
    assert token
    created = Organization.create(f"TP Org {tag}", f"tp-org-{tag}", user_id)
    assert created and created["org_id"]
    return _auth_headers(token), created["org_id"], user_id, tag


@pytest.fixture
def viewer_headers():
    from picosentry.serve.api.server import auth_service

    tag = uuid.uuid4().hex[:8]
    user_id = auth_service.create_user(f"tp-view-{tag}", "testpassword123", role="viewer")
    assert user_id
    token = auth_service.authenticate(f"tp-view-{tag}", "testpassword123")
    assert token
    return _auth_headers(token), user_id, tag


def _seed_alerts(org_id: int, n: int) -> None:
    base = datetime.now(timezone.utc)
    for i in range(n):
        db.execute_insert(
            """
            INSERT INTO alerts (project_id, alert_type, severity, message, channel, sent, created_at, org_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (f"proj-{i}", "test_alert", "low", f"alert {i}", "log", 0, base - timedelta(minutes=i), org_id),
        )


class TestTierQuotas:
    def test_member_quota_exceeded_rejects_with_no_row(self, client, admin_headers):
        from picosentry.serve.api.server import auth_service

        headers, org_id, _owner, tag = admin_headers
        invitee = auth_service.create_user(f"tp-invitee-{tag}", "testpassword123")
        assert invitee

        # free tier: users=1 (the owner) — one more member exceeds it.
        resp = client.post(
            f"/orgs/{org_id}/members",
            json={"user_id": invitee, "role": "viewer"},
            headers=headers,
        )
        assert resp.status_code == 402
        assert "member" in resp.json()["detail"].lower()

        members = db.execute("SELECT user_id FROM org_users WHERE org_id = ? AND user_id = ?", (org_id, invitee))
        assert members == [], "quota-rejected invite must not create a membership row"
        invites = db.execute("SELECT id FROM org_invites WHERE org_id = ?", (org_id,))
        assert invites == []

    def test_member_quota_tier_raise_allows_invite(self, client, admin_headers):
        from picosentry.serve.api.server import auth_service
        from picosentry.serve.services.orgs import Organization

        headers, org_id, _owner, tag = admin_headers
        invitee = auth_service.create_user(f"tp-starter-{tag}", "testpassword123")
        assert Organization.update_tier(org_id, "starter")  # users=5

        resp = client.post(
            f"/orgs/{org_id}/members",
            json={"user_id": invitee, "role": "operator"},
            headers=headers,
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["user_id"] == invitee
        assert body["role"] == "operator"
        assert body["invite_token"].startswith("inv_")

        roles = db.execute_one("SELECT role FROM org_users WHERE org_id = ? AND user_id = ?", (org_id, invitee))
        assert roles["role"] == "operator"

    def _fake_project(self, monkeypatch, project_id: str):
        """Register a runnable project on the app orchestrator (no subprocess)."""
        from picosentry.serve.services import orchestrator as orch_mod
        from picosentry.serve.services._orchestrator_data import PICO_CLI, ProjectMeta

        monkeypatch.setitem(
            orch_mod.orchestrator.registry,
            project_id,
            ProjectMeta(
                id=project_id,
                name=f"Quota {project_id}",
                category="scan",
                priority=1,
                dependencies=[],
                cron_schedule="",
                estimated_duration=1,
                status="active",
                version="1.0.0",
                package="echo",
            ),
        )
        monkeypatch.setitem(PICO_CLI, project_id, ["echo", "ok"])
        monkeypatch.setattr(
            orch_mod.subprocess,
            "run",
            lambda *a, **k: SimpleNamespace(returncode=0, stdout="ok", stderr=""),
        )

    def test_project_quota_rejected_at_run_trigger(self, client, admin_headers, monkeypatch):
        headers, org_id, _owner, _tag = admin_headers
        # free tier: projects=3 — fill the quota with seeded associations.
        for i in range(3):
            db.execute_insert(
                "INSERT INTO org_projects (org_id, project_id, added_at) VALUES (?, ?, ?)",
                (org_id, f"filled-{i}", datetime.now(timezone.utc)),
            )
        self._fake_project(monkeypatch, "quota-new-proj")

        resp = client.post("/projects/quota-new-proj/run", headers=headers)
        assert resp.status_code == 402
        assert "project" in resp.json()["detail"].lower()

        runs = db.execute("SELECT id FROM project_runs WHERE org_id = ? AND project_id = 'quota-new-proj'", (org_id,))
        assert runs == [], "quota-rejected run must not create a run row"
        assoc = db.execute("SELECT id FROM org_projects WHERE org_id = ? AND project_id = 'quota-new-proj'", (org_id,))
        assert assoc == []

    def test_project_quota_allows_already_associated_project(self, client, admin_headers, monkeypatch):
        headers, org_id, _owner, _tag = admin_headers
        for i in range(3):
            db.execute_insert(
                "INSERT INTO org_projects (org_id, project_id, added_at) VALUES (?, ?, ?)",
                (org_id, f"filled-{i}", datetime.now(timezone.utc)),
            )
        self._fake_project(monkeypatch, "filled-0")

        # Re-running an associated project never hits the project cap.
        resp = client.post("/projects/filled-0/run", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_run_quota_daily_cap(self, client, admin_headers, monkeypatch):
        headers, org_id, _owner, _tag = admin_headers
        # free tier: runs_per_day=50 — seed today's quota as completed runs.
        now = datetime.now(timezone.utc)
        for i in range(50):
            db.execute_insert(
                "INSERT INTO project_runs (project_id, run_start, run_end, status, org_id) VALUES (?, ?, ?, ?, ?)",
                (f"seed-{i}", now, now, "completed", org_id),
            )
        db.execute_insert(
            "INSERT INTO org_projects (org_id, project_id, added_at) VALUES (?, ?, ?)",
            (org_id, "seed-0", now),
        )
        self._fake_project(monkeypatch, "seed-0")

        resp = client.post("/projects/seed-0/run", headers=headers)
        assert resp.status_code == 402
        assert "runs/day" in resp.json()["detail"]

        count = db.execute_one("SELECT COUNT(*) as c FROM project_runs WHERE org_id = ?", (org_id,))
        assert count["c"] == 50, "quota-rejected run must not create a run row"

    def test_usage_reports_counters_at_the_cap(self, client, admin_headers):
        headers, org_id, _owner, _tag = admin_headers
        now = datetime.now(timezone.utc)
        for i in range(3):
            db.execute_insert(
                "INSERT INTO org_projects (org_id, project_id, added_at) VALUES (?, ?, ?)",
                (org_id, f"u-{i}", now),
            )

        resp = client.get(f"/orgs/{org_id}/usage", headers=headers)
        assert resp.status_code == 200
        usage = resp.json()
        assert usage["projects"]["used"] == 3
        assert usage["projects"]["limit"] == 3
        assert usage["projects"]["pct"] == 100.0


class TestMemberLifecycle:
    def test_invite_list_role_change_remove(self, client, admin_headers):
        from picosentry.serve.api.server import auth_service
        from picosentry.serve.services.orgs import Organization

        headers, org_id, owner, tag = admin_headers
        assert Organization.update_tier(org_id, "pro")  # lifecycle test, not a quota test
        member = auth_service.create_user(f"tp-member-{tag}", "testpassword123")
        assert member

        resp = client.post(f"/orgs/{org_id}/members", json={"user_id": member, "role": "viewer"}, headers=headers)
        assert resp.status_code == 201
        assert resp.json()["invite_token"].startswith("inv_")

        resp = client.get(f"/orgs/{org_id}/members", headers=headers)
        assert resp.status_code == 200
        members = {m["id"]: m["role"] for m in resp.json()["members"]}
        assert members[owner] == "admin"
        assert members[member] == "viewer"

        resp = client.patch(f"/orgs/{org_id}/members/{member}", json={"role": "operator"}, headers=headers)
        assert resp.status_code == 200
        assert resp.json() == {"user_id": member, "role": "operator"}

        resp = client.delete(f"/orgs/{org_id}/members/{member}", headers=headers)
        assert resp.status_code == 200
        assert resp.json() == {"user_id": member, "removed": True}

        resp = client.get(f"/orgs/{org_id}/members", headers=headers)
        assert member not in {m["id"] for m in resp.json()["members"]}

    def test_invite_duplicate_member_conflicts(self, client, admin_headers):
        headers, org_id, owner, _tag = admin_headers
        resp = client.post(f"/orgs/{org_id}/members", json={"user_id": owner, "role": "viewer"}, headers=headers)
        assert resp.status_code == 409

    def test_invite_unknown_user_404(self, client, admin_headers):
        headers, org_id, _owner, _tag = admin_headers
        resp = client.post(f"/orgs/{org_id}/members", json={"user_id": 987654321, "role": "viewer"}, headers=headers)
        assert resp.status_code == 404

    def test_invite_rejects_unknown_fields(self, client, admin_headers):
        headers, org_id, _owner, _tag = admin_headers
        resp = client.post(
            f"/orgs/{org_id}/members",
            json={"user_id": 1, "role": "viewer", "is_owner": True},
            headers=headers,
        )
        assert resp.status_code == 422

    def test_owner_cannot_be_removed_or_demoted(self, client, admin_headers):
        headers, org_id, owner, _tag = admin_headers
        assert client.delete(f"/orgs/{org_id}/members/{owner}", headers=headers).status_code == 409
        assert (
            client.patch(f"/orgs/{org_id}/members/{owner}", json={"role": "viewer"}, headers=headers).status_code == 409
        )

    def test_non_admin_forbidden(self, client, admin_headers, viewer_headers):
        _headers, org_id, _owner, tag = admin_headers
        v_headers, viewer, _vtag = viewer_headers
        # The viewer is not even a member -> 403 at membership check.
        assert (
            client.post(
                f"/orgs/{org_id}/members", json={"user_id": viewer, "role": "viewer"}, headers=v_headers
            ).status_code
            == 403
        )

        # Make the viewer an org member: still not an org admin -> 403.
        db.execute_insert(
            "INSERT INTO org_users (org_id, user_id, role) VALUES (?, ?, 'viewer')",
            (org_id, viewer),
        )
        assert (
            client.post(
                f"/orgs/{org_id}/members", json={"user_id": viewer, "role": "viewer"}, headers=v_headers
            ).status_code
            == 403
        )
        assert client.delete(f"/orgs/{org_id}/members/{viewer}", headers=v_headers).status_code == 403
        # Global admin role without membership in THIS org cannot touch it.
        other_admin = _make_admin_with_org(f"oa-{tag}")
        assert (
            client.post(
                f"/orgs/{org_id}/members",
                json={"user_id": viewer, "role": "viewer"},
                headers=_auth_headers(other_admin[0]),
            ).status_code
            == 403
        )

    def test_org_a_admin_cannot_touch_org_b_members(self, client, admin_headers):
        headers, _org_a, _owner, tag = admin_headers
        other = _make_admin_with_org(f"ob-{tag}")
        org_b = other[1]

        resp = client.post(f"/orgs/{org_b}/members", json={"user_id": other[2], "role": "viewer"}, headers=headers)
        assert resp.status_code == 403
        assert client.delete(f"/orgs/{org_b}/members/{other[2]}", headers=headers).status_code == 403


def _make_admin_with_org(tag: str):
    from picosentry.serve.api.server import auth_service
    from picosentry.serve.services.orgs import Organization

    user_id = auth_service.create_user(f"tp-{tag}", "testpassword123", role="admin")
    token = auth_service.authenticate(f"tp-{tag}", "testpassword123")
    created = Organization.create(f"TP {tag}", f"tp-{tag}", user_id)
    assert created
    return token, created["org_id"], user_id


class TestOrgSwitchHeader:
    @pytest.fixture
    def two_org_user(self):
        from picosentry.serve.api.server import auth_service
        from picosentry.serve.services.orgs import Organization

        tag = uuid.uuid4().hex[:8]
        user_id = auth_service.create_user(f"tp-switch-{tag}", "testpassword123", role="viewer")
        token = auth_service.authenticate(f"tp-switch-{tag}", "testpassword123")
        org_a = Organization.create("TP Switch A", f"tpsw-a-{tag}", user_id)
        org_b = Organization.create("TP Switch B", f"tpsw-b-{tag}", user_id)
        assert org_a and org_b

        now = datetime.now(timezone.utc)
        for org, pid in (
            (org_a["org_id"], f"sw-a-{tag}"),
            (org_b["org_id"], f"sw-b-{tag}"),
        ):
            db.execute_insert(
                """
                INSERT INTO projects (id, name, category, priority, status, version)
                VALUES (?, ?, 'scan', 1, 'active', '1.0')
            """,
                (pid, pid),
            )
            db.execute_insert(
                "INSERT INTO org_projects (org_id, project_id, added_at) VALUES (?, ?, ?)",
                (org, pid, now),
            )
        return _auth_headers(token), org_a["org_id"], org_b["org_id"], tag

    def test_header_selects_org_scoped_data(self, client, two_org_user):
        headers, org_a, org_b, tag = two_org_user

        with_a = client.get("/projects", headers={**headers, "X-Org-Id": str(org_a)})
        assert with_a.status_code == 200
        assert [p["id"] for p in with_a.json()] == [f"sw-a-{tag}"]

        with_b = client.get("/projects", headers={**headers, "X-Org-Id": str(org_b)})
        assert [p["id"] for p in with_b.json()] == [f"sw-b-{tag}"]

    def test_no_header_keeps_first_org_default(self, client, two_org_user):
        headers, _org_a, _org_b, tag = two_org_user
        resp = client.get("/projects", headers=headers)
        assert resp.status_code == 200
        # Backward compatible: some org the user belongs to, never a foreign one.
        assert [p["id"] for p in resp.json()] in ([f"sw-a-{tag}"], [f"sw-b-{tag}"])

    def test_non_member_org_403(self, client, two_org_user):
        from picosentry.serve.services.orgs import Organization

        headers, _a, _b, _tag = two_org_user
        stranger = _make_admin_with_org(f"str-{uuid.uuid4().hex[:6]}")
        foreign_org = Organization.create("TP Foreign", f"tpfor-{uuid.uuid4().hex[:8]}", stranger[2])["org_id"]

        resp = client.get("/projects", headers={**headers, "X-Org-Id": str(foreign_org)})
        assert resp.status_code == 403

    def test_malformed_header_400(self, client, two_org_user):
        headers, _a, _b, _tag = two_org_user
        resp = client.get("/projects", headers={**headers, "X-Org-Id": "not-a-number"})
        assert resp.status_code == 400


class TestOffsetPagination:
    def test_alerts_offset_pagination(self, client, admin_headers):
        headers, org_id, _owner, _tag = admin_headers
        _seed_alerts(org_id, 25)

        pages = [client.get(f"/alerts?limit=10&offset={o}", headers=headers).json() for o in (0, 10, 20, 30)]
        assert [len(p) for p in pages] == [10, 10, 5, 0]
        ids = [a["id"] for page in pages for a in page]
        assert len(ids) == len(set(ids)), "pages must not overlap"
        assert len(ids) == 25

    def test_alerts_pagination_is_org_scoped(self, client, admin_headers):
        headers, _org_id, _owner, tag = admin_headers
        other = _make_admin_with_org(f"pg-{tag}")
        _seed_alerts(other[1], 5)
        _seed_alerts(_org_id, 3)

        mine = {a["id"] for a in client.get("/alerts?limit=200", headers=headers).json()}
        foreign = {a["id"] for a in client.get("/alerts?limit=200", headers=_auth_headers(other[0])).json()}
        assert len(mine) == 3 and len(foreign) == 5
        assert not (mine & foreign)

    def test_projects_offset_pagination(self, client, admin_headers):
        headers, org_id, _owner, _tag = admin_headers
        now = datetime.now(timezone.utc)
        for i in range(12):
            db.execute_insert(
                """
                INSERT INTO projects (id, name, category, priority, status, version)
                VALUES (?, ?, 'scan', ?, 'active', '1.0')
            """,
                (f"pg-proj-{i:02d}", f"pg-proj-{i:02d}", i),
            )
            db.execute_insert(
                "INSERT INTO org_projects (org_id, project_id, added_at) VALUES (?, ?, ?)",
                (org_id, f"pg-proj-{i:02d}", now),
            )

        page1 = client.get("/projects?limit=5&offset=0", headers=headers).json()
        page2 = client.get("/projects?limit=5&offset=5", headers=headers).json()
        page3 = client.get("/projects?limit=5&offset=10", headers=headers).json()
        assert [len(p) for p in (page1, page2, page3)] == [5, 5, 2]
        ids = [p["id"] for p in (*page1, *page2, *page3)]
        assert len(set(ids)) == 12

    def test_intelligence_offset_pagination(self, client, admin_headers):
        headers, org_id, _owner, _tag = admin_headers
        base = datetime.now(timezone.utc)
        for i in range(15):
            db.execute_insert(
                """
                INSERT INTO intelligence (source_project, intel_type, severity, data, confidence, created_at, org_id)
                VALUES (?, 'test', 'low', '{}', 0.5, ?, ?)
            """,
                (f"intel-{i:02d}", base - timedelta(minutes=i), org_id),
            )

        page1 = client.get("/intelligence?limit=7&offset=0", headers=headers).json()
        page2 = client.get("/intelligence?limit=7&offset=7", headers=headers).json()
        page3 = client.get("/intelligence?limit=7&offset=14", headers=headers).json()
        assert [len(p) for p in (page1, page2, page3)] == [7, 7, 1]
        seen = [i["id"] for p in (page1, page2, page3) for i in p]
        assert len(set(seen)) == 15
