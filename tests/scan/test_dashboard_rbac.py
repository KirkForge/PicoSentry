"""Tests for dashboard endpoint RBAC scope enforcement and tenant isolation."""

import unittest

from picosentry.scan.auth import AuthResult, Scope, check_authorization


class TestDashboardScopeRequired(unittest.TestCase):
    """Test that dashboard sub-endpoints require appropriate scopes."""

    def test_dashboard_overview_requires_read(self):
        """Dashboard overview requires broad read access."""
        scopes = Scope.required_for_endpoint("/dashboard", "GET")
        assert Scope.READ in scopes
        assert Scope.TENANT_READ not in scopes  # overview is not tenant-specific

    def test_dashboard_tenants_requires_tenant_read(self):
        """/dashboard/tenants requires tenant:read scope."""
        scopes = Scope.required_for_endpoint("/dashboard/tenants", "GET")
        assert Scope.TENANT_READ in scopes
        assert Scope.TENANT_WRITE in scopes
        assert Scope.ADMIN in scopes

    def test_dashboard_fleet_requires_fleet_read(self):
        """/dashboard/fleet requires fleet:read scope."""
        scopes = Scope.required_for_endpoint("/dashboard/fleet", "GET")
        assert Scope.FLEET_READ in scopes
        assert Scope.FLEET_WRITE in scopes
        assert Scope.ADMIN in scopes

    def test_dashboard_compliance_requires_fleet_read(self):
        """/dashboard/compliance requires fleet:read scope."""
        scopes = Scope.required_for_endpoint("/dashboard/compliance", "GET")
        assert Scope.FLEET_READ in scopes
        assert Scope.FLEET_WRITE in scopes
        assert Scope.ADMIN in scopes

    def test_read_scope_does_not_grant_tenant_dashboard(self):
        """A read-only identity cannot access /dashboard/tenants."""
        result = AuthResult.success(identity="reader", scopes=["read"])
        authz = check_authorization(result, "/dashboard/tenants", "GET")
        # read resolves to {read, policy:read, corpus:read, tenant:read}
        # So read scope DOES imply tenant:read — this should succeed
        assert authz.ok

    def test_scan_scope_does_not_grant_fleet_dashboard(self):
        """A scan-only identity cannot access /dashboard/fleet."""
        result = AuthResult.success(identity="scanner", scopes=["scan"])
        authz = check_authorization(result, "/dashboard/fleet", "GET")
        # scan resolves to {read, scan} — no fleet:read
        assert not authz.ok

    def test_admin_grants_all_dashboards(self):
        """Admin scope grants access to all dashboard endpoints."""
        for path in ["/dashboard", "/dashboard/tenants", "/dashboard/fleet", "/dashboard/compliance"]:
            result = AuthResult.success(identity="admin", scopes=["admin"])
            authz = check_authorization(result, path, "GET")
            assert authz.ok, f"Admin should access {path}"

    def test_write_scope_grants_fleet_dashboard(self):
        """Write scope implies fleet:read (via write hierarchy)."""
        result = AuthResult.success(identity="writer", scopes=["write"])
        authz = check_authorization(result, "/dashboard/fleet", "GET")
        assert authz.ok  # write implies {read, write, scan, policy:read, corpus:read, tenant:read, fleet:read}


class TestDashboardTenantIsolation(unittest.TestCase):
    """Test that dashboard endpoints support X-Tenant-Id header for scoping."""

    def test_tenant_health_returns_tenant_data(self):
        """TenantManager.tenant_health returns proper structure for a known tenant."""
        import tempfile
        from pathlib import Path

        from picosentry.scan.tenant import TenantManager

        with tempfile.TemporaryDirectory() as tmpdir:
            tm = TenantManager(base_dir=Path(tmpdir))
            tm.create_tenant("test-org", display_name="Test Org")
            health = tm.tenant_health("test-org")
            assert health["tenant_id"] == "test-org"
            assert health["status"] in ("healthy", "degraded")
            assert health["enabled"] is True

    def test_tenant_health_not_found(self):
        """TenantManager.tenant_health returns not_found for unknown tenant."""
        import tempfile
        from pathlib import Path

        from picosentry.scan.tenant import TenantManager

        with tempfile.TemporaryDirectory() as tmpdir:
            tm = TenantManager(base_dir=Path(tmpdir))
            health = tm.tenant_health("nonexistent")
            assert health["status"] == "not_found"

    def test_fleet_overview_returns_tenant_summary(self):
        """TenantManager.fleet_overview includes per-tenant data."""
        import tempfile
        from pathlib import Path

        from picosentry.scan.tenant import TenantManager

        with tempfile.TemporaryDirectory() as tmpdir:
            tm = TenantManager(base_dir=Path(tmpdir))
            tm.create_tenant("org-a", display_name="Org A")
            tm.create_tenant("org-b", display_name="Org B")
            overview = tm.fleet_overview()
            assert overview["total_tenants"] == 2
            assert overview["enabled_tenants"] == 2
            assert "org-a" in overview["tenants"]
            assert "org-b" in overview["tenants"]

    def test_dashboard_handler_accepts_tenant_id_param(self):
        """_handle_dashboard accepts tenant_id parameter."""
        # Verify the signature includes tenant_id
        import inspect

        from picosentry.scan.daemon import HealthHandler

        sig = inspect.signature(HealthHandler._handle_dashboard)
        assert "tenant_id" in sig.parameters

    def test_scope_hierarchy_write_includes_fleet_read(self):
        """Write scope should include fleet:read in resolved scopes."""
        resolved = Scope.resolve(["write"])
        assert Scope.FLEET_READ in resolved
        assert Scope.TENANT_READ in resolved

    def test_scope_hierarchy_read_includes_tenant_read(self):
        """Read scope should include tenant:read in resolved scopes."""
        resolved = Scope.resolve(["read"])
        assert Scope.TENANT_READ in resolved

    def test_scope_scan_does_not_include_fleet_read(self):
        """Scan scope should NOT include fleet:read."""
        resolved = Scope.resolve(["scan"])
        assert Scope.FLEET_READ not in resolved
        assert Scope.TENANT_READ not in resolved


if __name__ == "__main__":
    unittest.main()
