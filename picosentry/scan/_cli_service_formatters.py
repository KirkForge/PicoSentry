"""Output formatting helpers for the scan CLI service."""

from __future__ import annotations

import sys

from picosentry.scan.formatters.table import _PINCH_LABELS
from picosentry.scan.models import ScanResult, Severity


def _format_summary(result: ScanResult) -> str:
    if not result.findings:
        return "PicoSentry: No pinches. All clear. 🦞"

    parts = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        count = result.stats.findings_by_severity.get(sev.value, 0)
        if count > 0:
            pinch = _PINCH_LABELS.get(sev, sev.value)
            parts.append(f"{count} {pinch}")

    return f"PicoSentry: {', '.join(parts)}"


def _format_quiet(result: ScanResult) -> str:
    if not result.findings:
        return "🦞 No pinches. All clear."

    lines = []
    lines.append(f"🦞 PicoSentry: {len(result.findings)} finding(s)")
    lines.append(f"  Target: {result.target}")
    lines.append(f"  Engine: v{result.engine_version} | Corpus: v{result.corpus_version}")
    lines.append(f"  Duration: {result.stats.duration_ms}ms")
    lines.append("")

    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        count = result.stats.findings_by_severity.get(sev.value, 0)
        if count > 0:
            pinch = _PINCH_LABELS.get(sev, sev.value)
            lines.append(f"  {pinch}: {count}")

    lines.append("")
    for rule_id in sorted(result.stats.findings_by_rule):
        count = result.stats.findings_by_rule[rule_id]
        lines.append(f"  {rule_id}: {count}")

    return "\n".join(lines)


def _print_verbose_details(result: ScanResult) -> None:
    print("\n--- Scan Details ---", file=sys.stderr)
    print(f"Engine: v{result.engine_version}", file=sys.stderr)
    print(f"Corpus: v{result.corpus_version}", file=sys.stderr)
    print(f"Scan ID: {result.scan_id}", file=sys.stderr)
    print(f"Duration: {result.stats.duration_ms}ms", file=sys.stderr)
    print(f"Packages: {result.stats.packages_scanned}", file=sys.stderr)
    print(f"Files: {result.stats.files_scanned}", file=sys.stderr)
    if result.stats.rule_timings_ms:
        print("\nRule Timings:", file=sys.stderr)
        for rule_id in sorted(result.stats.rule_timings_ms):
            ms = result.stats.rule_timings_ms[rule_id]
            count = result.stats.findings_by_rule.get(rule_id, 0)
            print(f"  {rule_id:<18s} {ms:>5d}ms  ({count} findings)", file=sys.stderr)
    if result.stats.findings_by_severity:
        print("\nSeverity Summary:", file=sys.stderr)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = result.stats.findings_by_severity.get(sev, 0)
            if count > 0:
                pinch = _PINCH_LABELS.get(Severity(sev), sev)
                print(f"  {sev:<10s} ({pinch}): {count}", file=sys.stderr)
