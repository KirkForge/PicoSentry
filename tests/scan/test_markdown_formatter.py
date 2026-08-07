from __future__ import annotations

from picosentry._core.models import Severity
from picosentry.scan.formatters import format_markdown
from picosentry.scan.formatters.markdown import MarkdownFormatter
from picosentry.scan.models import (
    Confidence,
    Finding,
    ScanResult,
    ScanStats,
)


def _result(findings=None, engine_version="2.0.18", duration_ms=500):
    return ScanResult(
        target="/tmp/test",
        engine_version=engine_version,
        corpus_version="abc123",
        findings=findings or [],
        stats=ScanStats(
            packages_scanned=2,
            files_scanned=10,
            duration_ms=duration_ms,
        ),
    )


def _finding(
    rule_id="L2-POST-001",
    severity=Severity.HIGH,
    package="evil@1.0.0",
    file="evil/package.json",
    message="Post-install script",
    **kw,
):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        confidence=Confidence.EXACT,
        package=package,
        file=file,
        message=message,
        evidence=kw.get("evidence", "scripts.postinstall"),
        remediation=kw.get("remediation", "Remove script"),
        line=kw.get("line", 5),
        ecosystem=kw.get("ecosystem", "npm"),
    )


class TestMarkdownFormatterCleanScan:
    def test_clean_scan_shows_no_findings(self):
        md = format_markdown(_result())
        assert "No findings. Dependencies appear safe." in md

    def test_clean_scan_has_header(self):
        md = format_markdown(_result())
        assert md.startswith("## PicoSentry Security Scan")

    def test_clean_scan_has_footer(self):
        md = format_markdown(_result(engine_version="1.2.3"))
        assert "v1.2.3" in md

    def test_clean_scan_duration(self):
        md = format_markdown(_result(duration_ms=2500))
        assert "2.5s" in md

    def test_clean_scan_no_table(self):
        md = format_markdown(_result())
        assert "| Severity |" not in md


class TestMarkdownFormatterSingleFinding:
    def test_single_finding_has_table(self):
        md = format_markdown(_result(findings=[_finding()]))
        assert "| Severity | Rule | Package | File | Message |" in md

    def test_single_finding_row(self):
        md = format_markdown(_result(findings=[_finding()]))
        expected = "| HIGH | L2-POST-001 | evil@1.0.0 | evil/package.json | Post-install script |"
        assert expected in md

    def test_single_finding_summary(self):
        md = format_markdown(_result(findings=[_finding()]))
        assert "Found 1 findings (1 HIGH)" in md


class TestMarkdownFormatterSeveritySorting:
    def test_findings_sorted_by_severity(self):
        findings = [
            _finding(
                severity=Severity.LOW,
                rule_id="L2-LOW-001",
                message="low",
            ),
            _finding(
                severity=Severity.CRITICAL,
                rule_id="L2-CRIT-001",
                message="critical",
            ),
            _finding(
                severity=Severity.MEDIUM,
                rule_id="L2-MED-001",
                message="medium",
            ),
        ]
        md = format_markdown(_result(findings=findings))
        data_lines = [
            line
            for line in md.split("\n")
            if line.startswith("|") and line.count("|") > 2 and "Severity" not in line and "------" not in line
        ]
        assert data_lines[0].strip().startswith("| CRITICAL")
        assert data_lines[1].strip().startswith("| MEDIUM")
        assert data_lines[2].strip().startswith("| LOW")

    def test_severity_grouping_in_summary(self):
        findings = [
            _finding(severity=Severity.CRITICAL, rule_id="R1"),
            _finding(severity=Severity.CRITICAL, rule_id="R2"),
            _finding(severity=Severity.HIGH, rule_id="R3"),
            _finding(severity=Severity.INFO, rule_id="R4"),
        ]
        md = format_markdown(_result(findings=findings))
        assert "Found 4 findings (2 CRITICAL, 1 HIGH, 1 INFO)" in md

    def test_all_severity_levels_in_summary(self):
        findings = [
            _finding(severity=Severity.CRITICAL, rule_id="R1"),
            _finding(severity=Severity.HIGH, rule_id="R2"),
            _finding(severity=Severity.MEDIUM, rule_id="R3"),
            _finding(severity=Severity.LOW, rule_id="R4"),
            _finding(severity=Severity.INFO, rule_id="R5"),
        ]
        md = format_markdown(_result(findings=findings))
        assert "1 CRITICAL, 1 HIGH, 1 MEDIUM, 1 LOW, 1 INFO" in md


class TestMarkdownFormatterFooter:
    def test_footer_version(self):
        md = format_markdown(_result())
        assert "PicoSentry v" in md

    def test_footer_duration(self):
        md = format_markdown(_result(duration_ms=3000))
        assert "3.0s" in md

    def test_footer_zero_duration(self):
        md = format_markdown(_result(duration_ms=0))
        assert "0.0s" in md


class TestMarkdownFormatterRegistry:
    def test_format_markdown_in_all(self):
        from picosentry.scan.formatters import __all__

        assert "format_markdown" in __all__
        assert "MarkdownFormatter" in __all__

    def test_format_markdown_callable(self):
        assert callable(format_markdown)

    def test_markdown_formatter_class(self):
        result = _result()
        fmt = MarkdownFormatter(result)
        output = fmt.format()
        assert isinstance(output, str)
        assert "PicoSentry Security Scan" in output


class TestMarkdownEscape:
    def test_pipe_escaped(self):
        from picosentry.scan.formatters.markdown import _md_escape

        assert _md_escape("evil|name") == "evil\\|name"

    def test_bracket_escaped(self):
        from picosentry.scan.formatters.markdown import _md_escape

        assert _md_escape("evil[link]") == "evil\\[link]"

    def test_newline_replaced(self):
        from picosentry.scan.formatters.markdown import _md_escape

        assert _md_escape("line1\nline2") == "line1 line2"

    def test_table_with_pipe_in_package(self):
        finding = _finding(package="evil|pkg", message="|injection|")
        md = format_markdown(_result(findings=[finding]))
        assert "\\|" in md
        assert "|evil|pkg" not in md
