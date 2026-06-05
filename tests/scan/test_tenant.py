"""Tests for multi-tenant management module."""

import shutil
import unittest
from pathlib import Path

from picosentry.scan.tenant import TenantConfig, TenantManager


class TestTenantConfig(unittest.TestCase):
    """Test TenantConfig creation and serialization."""

    def test_defaults(self):
        """TenantConfig has sensible defaults."""
        tc = TenantConfig(tenant_id="org-alpha")
        self.assertEqual(tc.tenant_id, "org-alpha")
        self.assertTrue(tc.enabled)
        self.assertEqual(tc.plan, "standard")
        self.assertEqual(tc.rbac_scopes, ["read", "scan"])
        self.assertNotEqual(tc.created_at, "")

    def test_to_dict(self):
        """TenantConfig serializes to dict."""
        tc = TenantConfig(tenant_id="org-alpha", display_name="Alpha Corp", plan="enterprise")
        d = tc.to_dict()
        self.assertEqual(d["tenant_id"], "org-alpha")
        self.assertEqual(d["display_name"], "Alpha Corp")
        self.assertEqual(d["plan"], "enterprise")

    def test_from_dict(self):
        """TenantConfig deserializes from dict."""
        d = {"tenant_id": "org-alpha", "plan": "enterprise", "enabled": False}
        tc = TenantConfig.from_dict(d)
        self.assertEqual(tc.tenant_id, "org-alpha")
        self.assertFalse(tc.enabled)

    def test_path_properties_without_base(self):
        """Path properties return empty Path when base_path is not set."""
        tc = TenantConfig(tenant_id="test")
        self.assertEqual(tc.audit_dir, Path())
        self.assertEqual(tc.corpus_dir, Path())


class TestTenantManager(unittest.TestCase):
    """Test TenantManager lifecycle operations."""

    def setUp(self):
        import tempfile

        self.tmp_dir = tempfile.mkdtemp()
        self.tm = TenantManager(base_dir=Path(self.tmp_dir) / "tenants")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_create_tenant(self):
        """Tenants can be created with isolated directories."""
        tc = self.tm.create_tenant("org-alpha", display_name="Alpha Corp", plan="enterprise")
        self.assertEqual(tc.tenant_id, "org-alpha")
        self.assertEqual(tc.display_name, "Alpha Corp")
        self.assertTrue(tc.enabled)
        # Check directory structure
        self.assertTrue(tc.audit_dir.is_dir())
        self.assertTrue(tc.corpus_dir.is_dir())
        self.assertTrue(tc.policy_dir.is_dir())
        self.assertTrue(tc.ioc_dir.is_dir())
        self.assertTrue(tc.cache_dir.is_dir())

    def test_create_tenant_invalid_id(self):
        """Invalid tenant IDs are rejected."""
        with self.assertRaises(ValueError):
            self.tm.create_tenant("UPPERCASE")
        with self.assertRaises(ValueError):
            self.tm.create_tenant("a")  # too short
        with self.assertRaises(ValueError):
            self.tm.create_tenant("org alpha")  # spaces

    def test_create_duplicate_tenant(self):
        """Duplicate tenant IDs are rejected."""
        self.tm.create_tenant("org-alpha")
        with self.assertRaises(ValueError):
            self.tm.create_tenant("org-alpha")

    def test_get_tenant(self):
        """Tenants can be retrieved."""
        self.tm.create_tenant("org-alpha")
        tc = self.tm.get_tenant("org-alpha")
        self.assertIsNotNone(tc)
        self.assertEqual(tc.tenant_id, "org-alpha")

    def test_get_nonexistent_tenant(self):
        """Getting nonexistent tenant returns None."""
        self.assertIsNone(self.tm.get_tenant("nonexistent"))

    def test_list_tenants(self):
        """Tenants can be listed."""
        self.tm.create_tenant("org-alpha")
        self.tm.create_tenant("org-beta")
        tenants = self.tm.list_tenants()
        self.assertEqual(len(tenants), 2)

    def test_list_tenants_enabled_only(self):
        """Tenants can be filtered to enabled only."""
        self.tm.create_tenant("org-alpha")
        self.tm.create_tenant("org-beta")
        self.tm.disable_tenant("org-beta")
        enabled = self.tm.list_tenants(enabled_only=True)
        self.assertEqual(len(enabled), 1)
        self.assertEqual(enabled[0].tenant_id, "org-alpha")

    def test_update_tenant(self):
        """Tenants can be updated."""
        self.tm.create_tenant("org-alpha")
        tc = self.tm.update_tenant("org-alpha", display_name="Alpha Corp Updated", max_scans_per_day=100)
        self.assertEqual(tc.display_name, "Alpha Corp Updated")
        self.assertEqual(tc.max_scans_per_day, 100)

    def test_update_nonexistent_tenant(self):
        """Updating nonexistent tenant raises ValueError."""
        with self.assertRaises(ValueError):
            self.tm.update_tenant("nonexistent", display_name="X")

    def test_disable_tenant(self):
        """Tenants can be disabled."""
        self.tm.create_tenant("org-alpha")
        tc = self.tm.disable_tenant("org-alpha")
        self.assertFalse(tc.enabled)

    def test_enable_tenant(self):
        """Disabled tenants can be re-enabled."""
        self.tm.create_tenant("org-alpha")
        self.tm.disable_tenant("org-alpha")
        tc = self.tm.enable_tenant("org-alpha")
        self.assertTrue(tc.enabled)

    def test_delete_tenant_without_confirm(self):
        """Deleting a tenant without confirm raises ValueError."""
        self.tm.create_tenant("org-alpha")
        with self.assertRaises(ValueError):
            self.tm.delete_tenant("org-alpha")

    def test_delete_tenant_with_confirm(self):
        """Tenants can be deleted with confirmation."""
        self.tm.create_tenant("org-alpha")
        self.assertTrue(self.tm.delete_tenant("org-alpha", confirm=True))
        self.assertIsNone(self.tm.get_tenant("org-alpha"))

    def test_delete_nonexistent_tenant(self):
        """Deleting nonexistent tenant returns False."""
        result = self.tm.delete_tenant("nonexistent", confirm=True)
        self.assertFalse(result)

    def test_tenant_audit_path(self):
        """Tenant audit paths are correctly resolved."""
        self.tm.create_tenant("org-alpha")
        path = self.tm.tenant_audit_path("org-alpha")
        self.assertIsNotNone(path)
        self.assertTrue("org-alpha" in str(path))
        self.assertTrue(str(path).endswith("audit.jsonl"))

    def test_tenant_corpus_path(self):
        """Tenant corpus paths are correctly resolved."""
        self.tm.create_tenant("org-alpha")
        path = self.tm.tenant_corpus_path("org-alpha")
        self.assertIsNotNone(path)
        self.assertTrue("org-alpha" in str(path))

    def test_tenant_policy_path(self):
        """Tenant policy paths are correctly resolved."""
        self.tm.create_tenant("org-alpha")
        path = self.tm.tenant_policy_path("org-alpha")
        self.assertIsNotNone(path)
        self.assertTrue("org-alpha" in str(path))

    def test_nonexistent_tenant_paths(self):
        """Paths for nonexistent tenants return None."""
        self.assertIsNone(self.tm.tenant_audit_path("nonexistent"))
        self.assertIsNone(self.tm.tenant_corpus_path("nonexistent"))
        self.assertIsNone(self.tm.tenant_policy_path("nonexistent"))
        self.assertIsNone(self.tm.tenant_ioc_path("nonexistent"))
        self.assertIsNone(self.tm.tenant_cache_path("nonexistent"))

    def test_tenant_health(self):
        """Tenant health returns structured status."""
        self.tm.create_tenant("org-alpha")
        health = self.tm.tenant_health("org-alpha")
        self.assertEqual(health["tenant_id"], "org-alpha")
        self.assertEqual(health["status"], "healthy")
        self.assertTrue(health["directories_ok"])
        self.assertTrue(health["enabled"])

    def test_tenant_health_disabled(self):
        """Disabled tenants show 'disabled' status."""
        self.tm.create_tenant("org-alpha")
        self.tm.disable_tenant("org-alpha")
        health = self.tm.tenant_health("org-alpha")
        self.assertEqual(health["status"], "disabled")

    def test_tenant_health_nonexistent(self):
        """Health of nonexistent tenant returns not_found."""
        health = self.tm.tenant_health("nonexistent")
        self.assertEqual(health["status"], "not_found")

    def test_fleet_overview(self):
        """Fleet overview returns summary across all tenants."""
        self.tm.create_tenant("org-alpha", plan="enterprise")
        self.tm.create_tenant("org-beta", plan="standard")
        overview = self.tm.fleet_overview()
        self.assertEqual(overview["total_tenants"], 2)
        self.assertEqual(overview["enabled_tenants"], 2)
        self.assertIn("org-alpha", overview["tenants"])
        self.assertIn("org-beta", overview["tenants"])

    def test_tenant_rbac_scopes(self):
        """Tenants can be created with custom RBAC scopes."""
        tc = self.tm.create_tenant("org-alpha", rbac_scopes=["admin", "scan"])
        self.assertEqual(tc.rbac_scopes, ["admin", "scan"])

    def test_tenant_max_scans(self):
        """Tenants can have rate limits."""
        tc = self.tm.create_tenant("org-alpha", max_scans_per_day=100)
        self.assertEqual(tc.max_scans_per_day, 100)

    def test_tenant_max_targets(self):
        """Tenants can have target limits."""
        tc = self.tm.create_tenant("org-alpha", max_targets=50)
        self.assertEqual(tc.max_targets, 50)


if __name__ == "__main__":
    unittest.main()
