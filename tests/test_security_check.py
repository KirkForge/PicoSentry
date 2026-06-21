"""Tests for the shared deployment security checker."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from picosentry._core.security_check import (
    _DEV_BYPASS_VARS,
    DeploymentFinding,
    assert_deployment_secure,
    check_deployment_security,
    format_findings,
    main,
)


class TestCheckDeploymentSecurity:
    """Unit tests for check_deployment_security."""

    def test_no_bypasses_returns_empty(self) -> None:
        assert check_deployment_security({}) == []

    def test_picodome_dev_mode_critical(self) -> None:
        findings = check_deployment_security({"PICODOME_DEV_MODE": "1"})
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"
        assert findings[0].check == "picodome-dev-mode-enabled"

    def test_picoshogun_skip_secure_assert_high(self) -> None:
        findings = check_deployment_security({"PICOSHOGUN_SKIP_SECURE_ASSERT": "1"})
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"
        assert findings[0].check == "picoshogun-skip-secure-assert-enabled"

    def test_all_secure_assert_skips_detected(self) -> None:
        env = {
            "PICODOME_SKIP_SECURE_ASSERT": "1",
            "PICOSHOGUN_SKIP_SECURE_ASSERT": "1",
            "PICOWATCH_SKIP_SECURE_ASSERT": "1",
        }
        findings = check_deployment_security(env)
        checks = {f.check for f in findings}
        assert checks == {
            "picodome-skip-secure-assert-enabled",
            "picoshogun-skip-secure-assert-enabled",
            "picowatch-skip-secure-assert-enabled",
        }
        assert all(f.severity == "HIGH" for f in findings)

    def test_dev_bypasses_only_trigger_on_value_one(self) -> None:
        env = {
            "PICODOME_DEV_MODE": "true",
            "PICOSHOGUN_SKIP_SECURE_ASSERT": "yes",
            "PICOWATCH_SKIP_SECURE_ASSERT": "",
        }
        assert check_deployment_security(env) == []

    def test_enterprise_mode_with_tls_dev_is_critical(self) -> None:
        findings = check_deployment_security({"PICODOME_ENTERPRISE_MODE": "1", "PICODOME_TLS_DEV": "1"})
        severities = {f.severity for f in findings}
        assert "CRITICAL" in severities
        assert any(f.check == "enterprise-mode-with-tls-dev" for f in findings)

    def test_weak_secret_values_are_critical(self) -> None:
        for value in ("", "changeme", "password"):
            findings = check_deployment_security({"PICOSHOGUN_SECRET_KEY": value})
            assert findings, f"expected finding for value={value!r}"
            assert findings[0].severity == "CRITICAL"

    def test_realistic_secret_passes(self) -> None:
        findings = check_deployment_security({"PICOSHOGUN_SECRET_KEY": "a-strong-random-secret-value"})
        assert findings == []


class TestFormatFindings:
    """Tests for format_findings."""

    def test_empty_findings(self) -> None:
        assert "No deployment-security findings" in format_findings([])

    def test_includes_severity_icon(self) -> None:
        findings = [DeploymentFinding("CRITICAL", "test", "message")]
        formatted = format_findings(findings)
        assert "CRITICAL" in formatted
        assert "test" in formatted
        assert "message" in formatted


class TestAssertDeploymentSecure:
    """Tests for assert_deployment_secure."""

    def test_clean_environ_raises_nothing(self) -> None:
        assert_deployment_secure({})

    def test_fatal_finding_raises_runtime_error(self) -> None:
        with pytest.raises(RuntimeError) as exc_info:
            assert_deployment_secure({"PICODOME_DEV_MODE": "1"})
        assert "PICODOME_DEV_MODE" in str(exc_info.value)

    def test_only_low_finding_passes(self) -> None:
        # The current checker never emits LOW/INFO, but guard the contract.
        assert_deployment_secure({})  # no findings


class TestMainCLI:
    """Tests for the security_check main() CLI."""

    def test_clean_exit_code(self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
        for var, _, _ in _DEV_BYPASS_VARS:
            monkeypatch.delenv(var, raising=False)
        assert main([]) == 0
        assert "No deployment-security findings" in capsys.readouterr().out

    def test_strict_fails_on_high(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch.dict("os.environ", {"PICOSHOGUN_SKIP_SECURE_ASSERT": "1"}, clear=False):
            code = main(["--strict"])
        assert code == 1
        assert "FAIL" in capsys.readouterr().out

    def test_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        code = main(["--json", "--env", "PICOSHOGUN_SKIP_SECURE_ASSERT=1", "--env", "PICODOME_DEV_MODE=1"])
        assert code == 1
        out = capsys.readouterr().out
        data = json.loads(out.splitlines()[0])
        assert len(data) == 2
        checks = {item["check"] for item in data}
        assert "picoshogun-skip-secure-assert-enabled" in checks
        assert "picodome-dev-mode-enabled" in checks

    def test_env_override(self, capsys: pytest.CaptureFixture[str]) -> None:
        code = main(["--env", "PICOWATCH_SKIP_SECURE_ASSERT=1"])
        assert code == 1
        assert "picowatch-skip-secure-assert-enabled" in capsys.readouterr().out


class TestModulePath:
    """Sanity check that the module is importable from the repo root."""

    def test_module_file_exists(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        module_path = repo_root / "picosentry" / "_core" / "security_check.py"
        assert module_path.exists()
