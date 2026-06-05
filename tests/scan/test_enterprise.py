"""Tests for enterprise mode enforcement."""

import os
import unittest

from picosentry.scan.enterprise import (
    ENV_ENTERPRISE_MODE,
    EXIT_AUTH_OFF,
    EXIT_INSECURE_CONFIG,
    EnterpriseViolation,
    enterprise_daemon_checks,
    enterprise_scan_checks,
    is_enterprise_mode,
    require_enterprise,
)


class TestEnterpriseMode(unittest.TestCase):
    """Test enterprise mode detection and enforcement."""

    def setUp(self):
        # Ensure enterprise mode is off before each test
        os.environ.pop(ENV_ENTERPRISE_MODE, None)

    def tearDown(self):
        os.environ.pop(ENV_ENTERPRISE_MODE, None)

    def test_enterprise_mode_off_by_default(self):
        assert not is_enterprise_mode()

    def test_enterprise_mode_on_with_env_1(self):
        os.environ[ENV_ENTERPRISE_MODE] = "1"
        assert is_enterprise_mode()

    def test_enterprise_mode_on_with_env_true(self):
        os.environ[ENV_ENTERPRISE_MODE] = "true"
        assert is_enterprise_mode()

    def test_enterprise_mode_off_with_env_empty(self):
        os.environ[ENV_ENTERPRISE_MODE] = ""
        assert not is_enterprise_mode()

    def test_enterprise_mode_off_with_env_no(self):
        os.environ[ENV_ENTERPRISE_MODE] = "no"
        assert not is_enterprise_mode()

    def test_require_enterprise_noop_when_off(self):
        """When enterprise mode is off, require_enterprise is a no-op."""
        require_enterprise("auth_not_off", "off")  # Should not raise

    def test_require_enterprise_auth_not_off_raises(self):
        """Enterprise mode rejects auth=off."""
        os.environ[ENV_ENTERPRISE_MODE] = "1"
        with self.assertRaises(EnterpriseViolation) as ctx:
            require_enterprise("auth_not_off", "off")
        assert ctx.exception.exit_code == EXIT_AUTH_OFF
        assert "auth=off" in str(ctx.exception)

    def test_require_enterprise_host_not_any_raises(self):
        """Enterprise mode rejects 0.0.0.0 binding."""
        os.environ[ENV_ENTERPRISE_MODE] = "1"
        with self.assertRaises(EnterpriseViolation) as ctx:
            require_enterprise("host_not_any", "0.0.0.0")
        assert ctx.exception.exit_code == EXIT_INSECURE_CONFIG
        assert "0.0.0.0" in str(ctx.exception)

    def test_require_enterprise_host_not_any_ipv6_raises(self):
        """Enterprise mode rejects :: binding."""
        os.environ[ENV_ENTERPRISE_MODE] = "1"
        with self.assertRaises(EnterpriseViolation) as ctx:
            require_enterprise("host_not_any", "::")
        assert ctx.exception.exit_code == EXIT_INSECURE_CONFIG

    def test_require_enterprise_version_pinned_raises(self):
        """Enterprise mode rejects version=latest."""
        os.environ[ENV_ENTERPRISE_MODE] = "1"
        with self.assertRaises(EnterpriseViolation):
            require_enterprise("version_pinned", "latest")

    def test_require_enterprise_version_pinned_allows_specific(self):
        """Enterprise mode allows pinned version."""
        os.environ[ENV_ENTERPRISE_MODE] = "1"
        require_enterprise("version_pinned", "0.15.0")  # Should not raise

    def test_require_enterprise_fail_on_rule_error_raises(self):
        """Enterprise mode requires fail-on-rule-error=True."""
        os.environ[ENV_ENTERPRISE_MODE] = "1"
        with self.assertRaises(EnterpriseViolation) as ctx:
            require_enterprise("fail_on_rule_error", False)
        assert ctx.exception.exit_code == EXIT_INSECURE_CONFIG

    def test_require_enterprise_fail_on_rule_error_allows(self):
        """Enterprise mode allows fail-on-rule-error=True."""
        os.environ[ENV_ENTERPRISE_MODE] = "1"
        require_enterprise("fail_on_rule_error", True)  # Should not raise

    def test_enterprise_daemon_checks_auth_off_raises(self):
        """Daemon with auth=off fails enterprise check."""
        os.environ[ENV_ENTERPRISE_MODE] = "1"
        with self.assertRaises(EnterpriseViolation):
            enterprise_daemon_checks("off", "0.0.0.0")

    def test_enterprise_daemon_checks_auth_token_warns(self):
        """Daemon with token auth passes but warns."""
        os.environ[ENV_ENTERPRISE_MODE] = "1"
        warnings = enterprise_daemon_checks("token", "127.0.0.1")
        assert len(warnings) == 1
        assert "OIDC" in warnings[0]

    def test_enterprise_daemon_checks_auth_oidc_ok(self):
        """Daemon with OIDC auth passes enterprise check."""
        os.environ[ENV_ENTERPRISE_MODE] = "1"
        warnings = enterprise_daemon_checks("oidc", "127.0.0.1")
        assert len(warnings) == 0

    def test_enterprise_daemon_checks_host_any_raises(self):
        """Daemon binding to 0.0.0.0 fails enterprise check."""
        os.environ[ENV_ENTERPRISE_MODE] = "1"
        with self.assertRaises(EnterpriseViolation):
            enterprise_daemon_checks("oidc", "0.0.0.0")

    def test_enterprise_scan_checks_fail_closed_required(self):
        """Scan must fail-closed in enterprise mode."""
        os.environ[ENV_ENTERPRISE_MODE] = "1"
        with self.assertRaises(EnterpriseViolation):
            enterprise_scan_checks(fail_on_rule_error=False)

    def test_enterprise_scan_checks_warns_empty_digests(self):
        """Scan warns about empty policy/config digests."""
        os.environ[ENV_ENTERPRISE_MODE] = "1"
        warnings = enterprise_scan_checks(fail_on_rule_error=True, policy_digest="", config_digest="")
        assert len(warnings) == 2


if __name__ == "__main__":
    unittest.main()
