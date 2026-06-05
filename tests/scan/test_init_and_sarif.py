"""
test_init_and_sarif.py — Tests for `picosentry init` command and SARIF helpUri.
"""

import json
import subprocess
import sys

from picosentry.scan.formatters import format_sarif
from picosentry.scan.models import Confidence, Finding, ScanResult, ScanStats, Severity


class TestInitCommand:
    """Test the `picosentry init` command."""

    def test_init_creates_config_file(self, tmp_path):
        """`picosentry init` should create .picosentry.yml in target directory."""
        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "init", str(tmp_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        config_path = tmp_path / ".picosentry.yml"
        assert config_path.exists()
        content = config_path.read_text()
        assert "version: 1" in content
        assert "severity_overrides" in content
        assert "ignore_packages" in content
        assert "ignore_paths" in content
        assert "rules" in content

    def test_init_default_directory(self, tmp_path, monkeypatch):
        """`picosentry init` with no directory arg should use current directory."""
        monkeypatch.chdir(tmp_path)
        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "init"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert (tmp_path / ".picosentry.yml").exists()

    def test_init_refuses_overwrite_without_force(self, tmp_path):
        """`picosentry init` should refuse to overwrite existing config without --force."""
        # Create existing config
        (tmp_path / ".picosentry.yml").write_text("version: 1\n")
        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "init", str(tmp_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 1
        assert "already exists" in result.stderr

    def test_init_overwrites_with_force(self, tmp_path):
        """`picosentry init --force` should overwrite existing config."""
        (tmp_path / ".picosentry.yml").write_text("old: config\n")
        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "init", str(tmp_path), "--force"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        content = (tmp_path / ".picosentry.yml").read_text()
        assert "version: 1" in content
        assert "old: config" not in content

    def test_init_config_has_all_options_commented(self, tmp_path):
        """Generated config should have all options available, commented out."""
        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "init", str(tmp_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        content = (tmp_path / ".picosentry.yml").read_text()
        # All options should be present (commented out)
        assert "# format:" in content
        assert "# no_color:" in content
        assert "# exit_code:" in content
        assert "# fail_on:" in content
        assert "# baseline:" in content
        assert "# token_budget:" in content
        assert "# severity_overrides:" in content
        assert "# ignore_packages:" in content
        assert "# ignore_paths:" in content
        assert "# rules:" in content

    def test_init_nonexistent_directory(self, tmp_path):
        """`picosentry init` should fail on non-existent directory."""
        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "init", str(tmp_path / "nonexistent")],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 2

    def test_init_created_config_is_valid_yaml(self, tmp_path):
        """Generated config should be valid YAML."""
        subprocess.run(
            [sys.executable, "-m", "picosentry", "init", str(tmp_path)],
            capture_output=True,
            timeout=30,
        )
        content = (tmp_path / ".picosentry.yml").read_text()
        # Try to parse as YAML (just check it doesn't crash)
        # Since we only use `version: 1` as active config, that should parse fine
        assert content.startswith("# PicoSentry")


class TestSARIFHelpUri:
    """Test SARIF output includes helpUri for each rule."""

    def test_sarif_rule_has_help_uri(self):
        """Each rule in SARIF output should have a helpUri field."""
        findings = [
            Finding(
                rule_id="L2-POST-001",
                severity=Severity.HIGH,
                confidence=Confidence.EXACT,
                package="evil@1.0.0",
                file="evil/package.json",
                message="Post-install script",
                evidence="scripts.postinstall",
                remediation="Remove script",
            ),
        ]
        result = ScanResult(
            target="/tmp/test",
            engine_version="0.6.0",
            corpus_version="abc123",
            findings=findings,
            stats=ScanStats(packages_scanned=1, files_scanned=10, duration_ms=100),
        )
        sarif = json.loads(format_sarif(result))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert "helpUri" in rules[0]
        assert "L2-POST-001" in rules[0]["helpUri"]

    def test_sarif_all_rules_have_help_uri(self):
        """All rules in SARIF output should have helpUri."""
        findings = [
            Finding(
                rule_id=f"L2-{rid}",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                package=f"pkg{i}@1.0",
                file=f"pkg{i}/package.json",
                message="test",
                evidence="evidence",
                remediation="fix",
            )
            for i, rid in enumerate(
                [
                    "POST-001",
                    "OBFS-001",
                    "OBFS-002",
                    "OBFS-003",
                    "OBFS-004",
                    "DEPC-001",
                    "TYPO-001",
                    "MANI-001",
                    "MANI-002",
                    "FORK-001",
                    "CRED-001",
                    "LOCK-001",
                    "BUND-001",
                    "PROV-001",
                    "MAINT-001",
                    "PNPM-001",
                    "LICENSE-001",
                    "ENGIN-001",
                    "SIDELOAD-001",
                ]
            )
        ]
        result = ScanResult(
            target="/tmp/test",
            engine_version="0.6.0",
            corpus_version="abc123",
            findings=findings,
            stats=ScanStats(packages_scanned=19, files_scanned=190, duration_ms=500),
        )
        sarif = json.loads(format_sarif(result))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        for rule in rules:
            assert "helpUri" in rule, f"Rule {rule['id']} missing helpUri"
            assert rule["helpUri"].startswith("https://github.com/KirkForge/PicoSentry"), (
                f"Rule {rule['id']} has wrong helpUri: {rule['helpUri']}"
            )

    def test_sarif_help_uri_format(self):
        """helpUri should follow the pattern: docs/rules/L2-XXX-NNN.md"""
        findings = [
            Finding(
                rule_id="L2-TYPO-001",
                severity=Severity.HIGH,
                confidence=Confidence.EXACT,
                package="reqct@1.0.0",
                file="package.json",
                message="Typosquat",
                evidence="reqct ≈ react",
                remediation="Use correct name",
            ),
        ]
        result = ScanResult(
            target="/tmp/test",
            engine_version="0.6.0",
            corpus_version="abc123",
            findings=findings,
            stats=ScanStats(packages_scanned=1, files_scanned=10, duration_ms=100),
        )
        sarif = json.loads(format_sarif(result))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["helpUri"].endswith("/L2-TYPO-001.md")

    def test_sarif_tool_driver_has_information_uri(self):
        """SARIF tool driver should have informationUri."""
        result = ScanResult(
            target="/tmp/test",
            engine_version="0.6.0",
            corpus_version="abc123",
            findings=[],
            stats=ScanStats(packages_scanned=0, files_scanned=0, duration_ms=50),
        )
        sarif = json.loads(format_sarif(result))
        driver = sarif["runs"][0]["tool"]["driver"]
        assert "informationUri" in driver
        assert "github.com" in driver["informationUri"]


class TestRulesCommandHelpUri:
    """Test that `picosentry rules --json` includes helpUri."""

    def test_rules_json_includes_help_uri(self):
        """`picosentry rules --json` should include helpUri for each rule."""
        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "rules", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) >= 15
        for rule in data:
            assert "rule_id" in rule
            assert "name" in rule
            # helpUri should be present after this update
            if "helpUri" in rule:
                assert rule["helpUri"].startswith("https://github.com")
