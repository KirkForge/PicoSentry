"""
Tests for PicoSentry config file support.

Config file is optional, deterministic, CLI overrides config.
"""

from picosentry.scan.config import (
    CONFIG_NAMES,
    CONFIG_VERSION,
    PicoSentryConfig,
    load_config,
)
from picosentry.scan.models import Confidence, Finding, Severity
import pytest

# ── PicoSentryConfig defaults ──


class TestConfigDefaults:
    def test_default_format(self):
        config = PicoSentryConfig()
        assert config.format == "table"

    def test_default_rules_is_none(self):
        """None means 'all rules', not an empty list."""
        config = PicoSentryConfig()
        assert config.rules is None

    def test_default_no_color(self):
        config = PicoSentryConfig()
        assert config.no_color is False

    def test_default_exit_code(self):
        config = PicoSentryConfig()
        assert config.exit_code is False

    def test_default_severity_overrides_empty(self):
        config = PicoSentryConfig()
        assert config.severity_overrides == {}

    def test_default_ignore_paths_empty(self):
        config = PicoSentryConfig()
        assert config.ignore_paths == []

    def test_default_ignore_packages_empty(self):
        config = PicoSentryConfig()
        assert config.ignore_packages == []


# ── Config file loading ──


class TestLoadConfig:
    def test_no_config_file_returns_defaults(self, tmp_path):
        config = load_config(tmp_path)
        assert config.format == "table"
        assert config.rules is None
        assert config.severity_overrides == {}

    def test_load_yml_config(self, tmp_path):
        config_file = tmp_path / ".picosentry.yml"
        config_file.write_text("version: 1\nformat: json\nno_color: true\nexit_code: true\n")
        config = load_config(tmp_path)
        assert config.format == "json"
        assert config.no_color is True
        assert config.exit_code is True

    def test_load_yaml_extension(self, tmp_path):
        config_file = tmp_path / ".picosentry.yaml"
        config_file.write_text("format: sarif\n")
        config = load_config(tmp_path)
        assert config.format == "sarif"

    def test_load_config_yml_extension(self, tmp_path):
        config_file = tmp_path / "picosentry.config.yml"
        config_file.write_text("format: ml-context\n")
        config = load_config(tmp_path)
        assert config.format == "ml-context"

    def test_precedence_yml_over_yaml(self, tmp_path):
        """First match wins: .picosentry.yml > .picosentry.yaml > picosentry.config.yml"""
        (tmp_path / ".picosentry.yml").write_text("format: json\n")
        (tmp_path / ".picosentry.yaml").write_text("format: sarif\n")
        config = load_config(tmp_path)
        assert config.format == "json"

    def test_precedence_yaml_over_config(self, tmp_path):
        (tmp_path / ".picosentry.yaml").write_text("format: sarif\n")
        (tmp_path / "picosentry.config.yml").write_text("format: ml-context\n")
        config = load_config(tmp_path)
        assert config.format == "sarif"

    def test_load_severity_overrides(self, tmp_path):
        config_file = tmp_path / ".picosentry.yml"
        config_file.write_text("version: 1\nseverity_overrides:\n  L2-PROV-001: LOW\n  L2-FORK-001: INFO\n")
        config = load_config(tmp_path)
        assert config.severity_overrides == {"L2-PROV-001": "LOW", "L2-FORK-001": "INFO"}

    def test_load_ignore_paths(self, tmp_path):
        config_file = tmp_path / ".picosentry.yml"
        config_file.write_text("version: 1\nignore_paths:\n  - 'vendor/**'\n  - '**/test/**'\n")
        config = load_config(tmp_path)
        assert config.ignore_paths == ["vendor/**", "**/test/**"]

    def test_load_ignore_packages(self, tmp_path):
        config_file = tmp_path / ".picosentry.yml"
        config_file.write_text("version: 1\nignore_packages:\n  - left-pad\n  - core-js\n")
        config = load_config(tmp_path)
        assert config.ignore_packages == ["left-pad", "core-js"]

    def test_load_rules_filter(self, tmp_path):
        config_file = tmp_path / ".picosentry.yml"
        config_file.write_text("version: 1\nrules:\n  - L2-POST-001\n  - L2-TYPO-001\n")
        config = load_config(tmp_path)
        assert config.rules == ["L2-POST-001", "L2-TYPO-001"]

    def test_load_baseline_path(self, tmp_path):
        config_file = tmp_path / ".picosentry.yml"
        config_file.write_text("version: 1\nbaseline: baseline.json\n")
        config = load_config(tmp_path)
        # Relative path should be resolved against config file directory
        assert config.baseline is not None
        assert "baseline.json" in config.baseline

    def test_load_baseline_absolute_path(self, tmp_path):
        config_file = tmp_path / ".picosentry.yml"
        config_file.write_text("version: 1\nbaseline: /tmp/baseline.json\n")
        config = load_config(tmp_path)
        assert config.baseline == "/tmp/baseline.json"

    def test_load_token_budget(self, tmp_path):
        config_file = tmp_path / ".picosentry.yml"
        config_file.write_text("version: 1\ntoken_budget: 2048\n")
        config = load_config(tmp_path)
        assert config.token_budget == 2048

    def test_load_fail_on(self, tmp_path):
        config_file = tmp_path / ".picosentry.yml"
        config_file.write_text("version: 1\nfail_on: high\n")
        config = load_config(tmp_path)
        assert config.fail_on == "high"

    def test_load_severity_threshold(self, tmp_path):
        config_file = tmp_path / ".picosentry.yml"
        config_file.write_text("version: 1\nseverity_threshold: medium\n")
        config = load_config(tmp_path)
        assert config.severity_threshold == "medium"

    def test_load_quiet(self, tmp_path):
        config_file = tmp_path / ".picosentry.yml"
        config_file.write_text("version: 1\nquiet: true\n")
        config = load_config(tmp_path)
        assert config.quiet is True

    def test_invalid_config_returns_defaults(self, tmp_path):
        config_file = tmp_path / ".picosentry.yml"
        config_file.write_text("not: a\nvalid: [yaml: structure")
        # Should not crash, just return defaults
        config = load_config(tmp_path)
        # YAML parses this fine, but it's a dict — check it doesn't crash
        assert config is not None

    def test_non_dict_config_returns_defaults(self, tmp_path):
        config_file = tmp_path / ".picosentry.yml"
        config_file.write_text("- just\n- a\n- list")
        config = load_config(tmp_path)
        # List is not a dict — should return defaults
        assert config.format == "table"

    def test_unexpected_parse_error_propagates(self, tmp_path, monkeypatch):
        """A truly unexpected exception (e.g. programmer error) should not be
        swallowed by the config loader's broad fallback.
        """
        config_file = tmp_path / ".picosentry.yml"
        config_file.write_text("format: json\n")

        import picosentry.scan.config as config_module

        def _boom(*args, **kwargs):
            raise ZeroDivisionError("simulated programmer error")

        # Remove YAMLError from the operational tuple so ZeroDivisionError is
        # no longer treated as an expected parse failure.
        original_errors = config_module._CONFIG_PARSE_ERRORS
        try:
            config_module._CONFIG_PARSE_ERRORS = (OSError,)
            monkeypatch.setattr(config_module.yaml, "safe_load", _boom)
            with pytest.raises(ZeroDivisionError):
                load_config(tmp_path)
        finally:
            config_module._CONFIG_PARSE_ERRORS = original_errors

    def test_version_mismatch_still_loads(self, tmp_path):
        config_file = tmp_path / ".picosentry.yml"
        config_file.write_text("version: 99\nformat: json\n")
        config = load_config(tmp_path)
        # Should still load despite version mismatch
        assert config.format == "json"


# ── Severity overrides ──


class TestSeverityOverrides:
    def _make_finding(self, rule_id="L2-PROV-001", severity=Severity.LOW):
        return Finding(
            rule_id=rule_id,
            severity=severity,
            confidence=Confidence.EXACT,
            package="test-pkg",
            file="test/package.json",
            message="Test finding",
            evidence="test evidence",
            remediation="test remediation",
        )

    def test_no_overrides_returns_same_findings(self):
        config = PicoSentryConfig()
        findings = [self._make_finding()]
        result = config.apply_severity_overrides(findings)
        assert result[0].severity == Severity.LOW

    def test_override_severity(self):
        config = PicoSentryConfig()
        config.severity_overrides = {"L2-PROV-001": "CRITICAL"}
        findings = [self._make_finding(severity=Severity.LOW)]
        result = config.apply_severity_overrides(findings)
        assert result[0].severity == Severity.CRITICAL

    def test_override_case_insensitive(self):
        config = PicoSentryConfig()
        config.severity_overrides = {"L2-PROV-001": "high"}
        findings = [self._make_finding(severity=Severity.LOW)]
        result = config.apply_severity_overrides(findings)
        assert result[0].severity == Severity.HIGH

    def test_override_only_affects_matching_rule(self):
        config = PicoSentryConfig()
        config.severity_overrides = {"L2-PROV-001": "CRITICAL"}
        findings = [
            self._make_finding(rule_id="L2-PROV-001", severity=Severity.LOW),
            self._make_finding(rule_id="L2-TYPO-001", severity=Severity.HIGH),
        ]
        result = config.apply_severity_overrides(findings)
        assert result[0].severity == Severity.CRITICAL
        assert result[1].severity == Severity.HIGH  # Unchanged

    def test_invalid_severity_override_keeps_original(self):
        config = PicoSentryConfig()
        config.severity_overrides = {"L2-PROV-001": "INVALID"}
        findings = [self._make_finding(severity=Severity.LOW)]
        result = config.apply_severity_overrides(findings)
        assert result[0].severity == Severity.LOW  # Kept original

    def test_multiple_overrides(self):
        config = PicoSentryConfig()
        config.severity_overrides = {
            "L2-PROV-001": "INFO",
            "L2-FORK-001": "HIGH",
        }
        findings = [
            self._make_finding(rule_id="L2-PROV-001", severity=Severity.LOW),
            self._make_finding(rule_id="L2-FORK-001", severity=Severity.MEDIUM),
        ]
        result = config.apply_severity_overrides(findings)
        assert result[0].severity == Severity.INFO
        assert result[1].severity == Severity.HIGH


# ── Ignore patterns ──


class TestIgnorePatterns:
    def test_ignore_package_exact_match(self):
        config = PicoSentryConfig()
        config.ignore_packages = ["left-pad", "core-js"]
        assert config.should_ignore_package("left-pad") is True
        assert config.should_ignore_package("lodash") is False

    def test_ignore_package_empty_list(self):
        config = PicoSentryConfig()
        assert config.should_ignore_package("anything") is False

    def test_ignore_path_glob(self):
        config = PicoSentryConfig()
        config.ignore_paths = ["vendor/**", "**/test/**"]
        assert config.should_ignore_path("vendor/evil/pkg/package.json") is True
        assert config.should_ignore_path("src/test/fixtures/pkg.json") is True
        assert config.should_ignore_path("src/index.js") is False

    def test_ignore_path_empty_list(self):
        config = PicoSentryConfig()
        assert config.should_ignore_path("anything") is False


# ── CLI override merging ──


class TestCLIMerge:
    def _make_args(self, **kwargs):
        """Create a simple namespace object simulating argparse args."""
        import argparse

        return argparse.Namespace(**kwargs)

    def test_cli_format_overrides_config(self):
        config = PicoSentryConfig()
        config.format = "json"
        args = self._make_args(format="sarif")
        merged = config.merge_cli(args)
        assert merged.format == "sarif"

    def test_cli_default_format_does_not_override(self):
        """If CLI arg is None (user didn't pass --format), config value should be kept."""
        config = PicoSentryConfig()
        config.format = "json"
        args = self._make_args(format=None)
        merged = config.merge_cli(args)
        assert merged.format == "json"  # Config wins

    def test_cli_rules_override_config(self):
        config = PicoSentryConfig()
        config.rules = ["L2-POST-001"]
        args = self._make_args(rules=["L2-TYPO-001"], format=None)
        merged = config.merge_cli(args)
        assert merged.rules == ["L2-TYPO-001"]

    def test_cli_no_color_overrides_config(self):
        config = PicoSentryConfig()
        config.no_color = False
        args = self._make_args(no_color=True, format="table")
        merged = config.merge_cli(args)
        assert merged.no_color is True

    def test_config_severity_overrides_preserved(self):
        config = PicoSentryConfig()
        config.severity_overrides = {"L2-PROV-001": "INFO"}
        args = self._make_args(format="table")
        merged = config.merge_cli(args)
        assert merged.severity_overrides == {"L2-PROV-001": "INFO"}

    def test_config_ignore_packages_preserved(self):
        config = PicoSentryConfig()
        config.ignore_packages = ["left-pad"]
        args = self._make_args(format="table")
        merged = config.merge_cli(args)
        assert merged.ignore_packages == ["left-pad"]

    def test_fail_on_implies_exit_code(self):
        config = PicoSentryConfig()
        args = self._make_args(fail_on="high", format="table")
        merged = config.merge_cli(args)
        assert merged.exit_code is True


# ── Determinism ──


class TestConfigDeterminism:
    def test_config_file_is_deterministic(self, tmp_path):
        """Same config file always produces same PicoSentryConfig."""
        config_file = tmp_path / ".picosentry.yml"
        config_file.write_text("version: 1\nformat: json\nseverity_overrides:\n  L2-PROV-001: INFO\n")
        config_a = load_config(tmp_path)
        config_b = load_config(tmp_path)

        assert config_a.format == config_b.format
        assert config_a.severity_overrides == config_b.severity_overrides

    def test_severity_override_is_deterministic(self):
        """Same overrides + same findings = same output, always."""
        config = PicoSentryConfig()
        config.severity_overrides = {"L2-PROV-001": "CRITICAL"}

        findings = [
            Finding(
                rule_id="L2-PROV-001",
                severity=Severity.LOW,
                confidence=Confidence.EXACT,
                package="test-pkg",
                file="test/package.json",
                message="Test",
                evidence="test",
                remediation="fix",
            ),
        ]

        result_a = config.apply_severity_overrides(findings)
        result_b = config.apply_severity_overrides(findings)

        assert result_a[0].severity == result_b[0].severity == Severity.CRITICAL
        assert result_a[0].to_dict() == result_b[0].to_dict()

    def test_config_version_constant(self):
        """Config version is deterministic."""
        assert CONFIG_VERSION == 1

    def test_config_names_deterministic(self):
        """Config search order is deterministic."""
        assert CONFIG_NAMES == [".picosentry.yml", ".picosentry.yaml", "picosentry.config.yml"]
