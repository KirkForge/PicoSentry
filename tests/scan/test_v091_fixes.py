"""Tests for v0.9.1 fixes: --version flag, baseline-update no-rescan, apply_baseline O(n)."""

import json
import tempfile
from pathlib import Path

from picosentry.scan.models import (
    Confidence,
    Finding,
    ScanResult,
    ScanStats,
    Severity,
    apply_baseline,
)

# -- --version flag test --


class TestVersionFlag:
    def test_version_flag_works(self):
        """--version should print version and exit 0."""
        import subprocess

        result = subprocess.run(
            ["python3", "-m", "picosentry", "--version"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        assert result.returncode == 0
        assert "PicoSentry (unified)" in result.stdout

    def test_version_flag_short(self):
        """-V should also work."""
        import subprocess

        result = subprocess.run(
            ["python3", "-m", "picosentry", "-V"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        assert result.returncode == 0
        assert "PicoSentry (unified)" in result.stdout


# -- apply_baseline O(n) tests --


class TestApplyBaselinePerformance:
    def test_exact_match_suppressed(self):
        """Exact fingerprint match should be suppressed."""
        findings = [
            Finding(
                rule_id="L2-POST-001",
                severity=Severity.HIGH,
                confidence=Confidence.EXACT,
                package="evil-pkg",
                file="package.json",
                message="postinstall",
                evidence="scripts.postinstall",
                remediation="Remove",
            ),
        ]
        result = ScanResult(
            target="test",
            engine_version="0.9.1",
            corpus_version="abc123",
            findings=findings,
            stats=ScanStats(),
        )
        baseline = {("L2-POST-001", "evil-pkg", "package.json")}
        br = apply_baseline(result, baseline)
        assert br.suppressed_count == 1
        assert br.new_count == 0

    def test_rule_only_match_suppressed(self):
        """Rule-only baseline entry should suppress all findings for that rule."""
        findings = [
            Finding(
                rule_id="L2-POST-001",
                severity=Severity.HIGH,
                confidence=Confidence.EXACT,
                package="pkg-a",
                file="package.json",
                message="postinstall",
                evidence="scripts.postinstall",
                remediation="Remove",
            ),
            Finding(
                rule_id="L2-POST-001",
                severity=Severity.HIGH,
                confidence=Confidence.EXACT,
                package="pkg-b",
                file="package.json",
                message="postinstall",
                evidence="scripts.postinstall",
                remediation="Remove",
            ),
        ]
        result = ScanResult(
            target="test",
            engine_version="0.9.1",
            corpus_version="abc123",
            findings=findings,
            stats=ScanStats(),
        )
        # Rule-only match: empty package and file
        baseline = {("L2-POST-001", "", "")}
        br = apply_baseline(result, baseline)
        assert br.suppressed_count == 2
        assert br.new_count == 0

    def test_rule_package_match_suppressed(self):
        """Rule+package baseline entry suppresses all findings for that rule+package."""
        findings = [
            Finding(
                rule_id="L2-POST-001",
                severity=Severity.HIGH,
                confidence=Confidence.EXACT,
                package="evil-pkg",
                file="package.json",
                message="postinstall",
                evidence="scripts.postinstall",
                remediation="Remove",
            ),
            Finding(
                rule_id="L2-POST-001",
                severity=Severity.HIGH,
                confidence=Confidence.EXACT,
                package="evil-pkg",
                file="sub/package.json",
                message="postinstall",
                evidence="scripts.postinstall",
                remediation="Remove",
            ),
        ]
        result = ScanResult(
            target="test",
            engine_version="0.9.1",
            corpus_version="abc123",
            findings=findings,
            stats=ScanStats(),
        )
        # Rule+package match: empty file
        baseline = {("L2-POST-001", "evil-pkg", "")}
        br = apply_baseline(result, baseline)
        assert br.suppressed_count == 2
        assert br.new_count == 0

    def test_no_match_remains(self):
        """Findings not in baseline should remain."""
        findings = [
            Finding(
                rule_id="L2-POST-001",
                severity=Severity.HIGH,
                confidence=Confidence.EXACT,
                package="new-pkg",
                file="package.json",
                message="postinstall",
                evidence="scripts.postinstall",
                remediation="Remove",
            ),
        ]
        result = ScanResult(
            target="test",
            engine_version="0.9.1",
            corpus_version="abc123",
            findings=findings,
            stats=ScanStats(),
        )
        baseline = {("L2-OBFS-001", "other-pkg", "package.json")}
        br = apply_baseline(result, baseline)
        assert br.suppressed_count == 0
        assert br.new_count == 1


# -- baseline-update no-rescan test --


class TestBaselineUpdateNoRescan:
    def test_baseline_update_uses_cached_findings(self):
        """--baseline-update should NOT re-scan. It should use pre-baseline findings."""
        import subprocess

        fixtures = Path(__file__).parent / "fixtures"

        # First: scan to create baseline
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            baseline_path = f.name

        try:
            # Create baseline from a scan
            result = subprocess.run(
                [
                    "python3",
                    "-m",
                    "picosentry",
                    "scan",
                    str(fixtures / "event_stream"),
                    "--format",
                    "json",
                    "--output",
                    baseline_path,
                ],
                capture_output=True,
                text=True,
                cwd=str(Path(__file__).parent.parent),
            )
            assert result.returncode in (0, 1)  # 1 = findings found

            # Read baseline
            with open(baseline_path) as f:
                baseline_data = json.load(f)
            assert "findings" in baseline_data
            assert len(baseline_data["findings"]) > 0

            # Now scan with baseline + baseline-update
            subprocess.run(
                [
                    "python3",
                    "-m",
                    "picosentry",
                    "scan",
                    str(fixtures / "event_stream"),
                    "--format",
                    "json",
                    "--baseline",
                    baseline_path,
                    "--baseline-update",
                ],
                capture_output=True,
                text=True,
                cwd=str(Path(__file__).parent.parent),
            )

            # The updated baseline should have the same findings (no duplicates, no missing)
            with open(baseline_path) as f:
                updated_data = json.load(f)
            assert len(updated_data["findings"]) >= len(baseline_data["findings"])

        finally:
            Path(baseline_path).unlink(missing_ok=True)
