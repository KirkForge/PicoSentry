"""
test_github.py — Tests for --format github output (SARIF file + markdown summary).
"""

import json
import os
from pathlib import Path
from unittest.mock import patch

from picosentry.scan.formatters.github import format_github
from picosentry.scan.models import Confidence, Finding, ScanResult, ScanStats, Severity


def _make_result(findings=None, target="/tmp/test", engine_version="0.9.0"):
    """Create a ScanResult with sensible defaults."""
    return ScanResult(
        target=target,
        engine_version=engine_version,
        corpus_version="abc123def456",
        findings=findings or [],
        stats=ScanStats(
            packages_scanned=len(findings) if findings else 0,
            files_scanned=10 * len(findings) if findings else 0,
            duration_ms=150,
        ),
    )


class TestFormatGitHub:
    """Test the format_github function directly."""

    def test_creates_sarif_file(self, tmp_path):
        """format_github should write a valid SARIF file."""
        result = _make_result(
            [
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
        )
        sarif_path = str(tmp_path / "output.sarif")
        format_github(result, sarif_path=sarif_path)

        # SARIF file should exist and be valid
        sarif_data = json.loads(Path(sarif_path).read_text())
        assert sarif_data["version"] == "2.1.0"
        assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "picosentry"
        assert len(sarif_data["runs"][0]["results"]) == 1

    def test_summary_contains_metadata(self, tmp_path):
        """Markdown summary should contain engine, corpus, scan ID."""
        result = _make_result([])
        sarif_path = str(tmp_path / "output.sarif")
        summary = format_github(result, sarif_path=sarif_path)

        assert "PicoSentry" in summary
        assert "Engine" in summary
        assert "Corpus" in summary
        assert "SARIF" in summary
        assert "output.sarif" in summary

    def test_clean_project_summary(self, tmp_path):
        """Clean project should show 'All clear' in summary."""
        result = _make_result([])
        sarif_path = str(tmp_path / "output.sarif")
        summary = format_github(result, sarif_path=sarif_path)

        assert "All clear" in summary

    def test_findings_table(self, tmp_path):
        """Summary should include findings table with rule IDs and packages."""
        result = _make_result(
            [
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
                    rule_id="L2-TYPO-001",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    package="reqct@1.0.0",
                    file="package.json",
                    message="Typosquat of react",
                    evidence="reqct ≈ react (edit distance 1)",
                    remediation="Use the correct package name",
                ),
            ]
        )
        result.recompute_stats()
        sarif_path = str(tmp_path / "output.sarif")
        summary = format_github(result, sarif_path=sarif_path)

        assert "L2-POST-001" in summary
        assert "L2-TYPO-001" in summary
        assert "evil@1.0.0" in summary
        assert "reqct@1.0.0" in summary
        assert "| Rule |" in summary

    def test_severity_breakdown(self, tmp_path):
        """Summary should show severity breakdown table."""
        result = _make_result(
            [
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
        )
        result.recompute_stats()  # Ensure findings_by_severity is populated
        sarif_path = str(tmp_path / "output.sarif")
        summary = format_github(result, sarif_path=sarif_path)

        assert "HIGH" in summary
        assert "HARD PINCH" in summary

    def test_truncation_at_50_findings(self, tmp_path):
        """Summary should truncate findings table at 50 entries."""
        findings = [
            Finding(
                rule_id="L2-TYPO-001",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                package=f"pkg{i}@1.0.0",
                file=f"pkg{i}/package.json",
                message=f"Typosquat of react ({i})",
                evidence=f"pkg{i} ≈ react",
                remediation="Use correct name",
            )
            for i in range(55)
        ]
        result = _make_result(findings)
        result.recompute_stats()
        sarif_path = str(tmp_path / "output.sarif")
        summary = format_github(result, sarif_path=sarif_path)

        assert "5 more finding(s)" in summary
        # Should still list first 50
        assert "pkg0@1.0.0" in summary
        assert "pkg49@1.0.0" in summary

    def test_github_step_summary_env(self, tmp_path):
        """If GITHUB_STEP_SUMMARY is set, summary should be appended to it."""
        result = _make_result(
            [
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
        )
        summary_file = tmp_path / "step_summary.md"
        summary_file.write_text("## Previous Step\n\nSome output.\n")

        sarif_path = str(tmp_path / "output.sarif")
        with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary_file)}):
            format_github(result, sarif_path=sarif_path)

        # Step summary file should have been appended to
        content = summary_file.read_text()
        assert "PicoSentry" in content
        assert "Previous Step" in content  # original content preserved

    def test_no_github_step_summary_env(self, tmp_path):
        """Without GITHUB_STEP_SUMMARY, format_github should still work."""
        result = _make_result([])
        sarif_path = str(tmp_path / "output.sarif")
        with patch.dict(os.environ, {}, clear=True):
            # Remove GITHUB_STEP_SUMMARY if present
            os.environ.pop("GITHUB_STEP_SUMMARY", None)
            summary = format_github(result, sarif_path=sarif_path)

        assert "All clear" in summary
        assert Path(sarif_path).exists()

    def test_deterministic_sarif_output(self, tmp_path):
        """Two calls to format_github should produce identical SARIF files."""
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
        result = _make_result(findings)

        sarif_a = str(tmp_path / "scan_a.sarif")
        sarif_b = str(tmp_path / "scan_b.sarif")

        format_github(result, sarif_path=sarif_a)
        format_github(result, sarif_path=sarif_b)

        content_a = Path(sarif_a).read_text()
        content_b = Path(sarif_b).read_text()
        assert content_a == content_b, "SARIF output must be deterministic"
