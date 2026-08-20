"""WO6.0.0-012: POST /orgs with tier=enterprise from a non-admin viewer
must clamp to `free` (mirroring the /upgrade dual gate); only a global
admin can create a paid-tier org directly.

Pre-fix: create_org gated only on get_current_user, so a viewer could
self-service enterprise (999 members / 99999 runs/day) — bypassing
exactly the control /orgs/{id}/upgrade enforces.
"""

from __future__ import annotations

from tests.serve._integration_helpers import _auth_headers, _register_and_login


class TestOrgCreateTierClamp:
    def test_viewer_cannot_self_service_paid_tier(self, client):
        """A viewer requesting tier=enterprise must get a `free` org back,
        not enterprise."""
        token, _ = _register_and_login(client, role="viewer")
        slug = f"wo6-clamp-viewer-{__import__('time').time_ns()}"
        resp = client.post(
            "/orgs",
            json={"name": "Clamp Viewer Org", "slug": slug, "tier": "enterprise"},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["tier"] == "free", f"viewer self-served paid tier: {body['tier']}"
        # Quotas follow the tier (free: 50 runs/day, not enterprise 99999).
        detail = client.get(f"/orgs/{body['id']}", headers=_auth_headers(token)).json()
        assert detail["tier"] == "free"

    def test_admin_can_create_paid_tier_directly(self, client):
        """A global admin can still seed a paid-tier org directly (no clamp)."""
        token, _ = _register_and_login(client, role="admin")
        slug = f"wo6-clamp-admin-{__import__('time').time_ns()}"
        resp = client.post(
            "/orgs",
            json={"name": "Clamp Admin Org", "slug": slug, "tier": "pro"},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["tier"] == "pro", "global admin clamp defeated paid tier"

    def test_operator_also_clamped(self, client):
        """Operator is not a global admin — clamp applies to non-admin roles
        generally, not just viewer."""
        token, _ = _register_and_login(client, role="operator")
        slug = f"wo6-clamp-op-{__import__('time').time_ns()}"
        resp = client.post(
            "/orgs",
            json={"name": "Clamp Op Org", "slug": slug, "tier": "enterprise"},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["tier"] == "free", "operator self-served paid tier"
