"""
Table formatter — human-readable terminal output with claw pinch branding.

Deterministic: findings sorted by (rule_id, package, file, line).
Machine formats (JSON, SARIF, ml-context) use standard severity labels.
Table format uses PicoSentry branding: HARD PINCH / SOFT PINCH / NUDGE.
"""

from picosentry.scan.models import ScanResult, Severity

# ANSI color codes
_COLORS = {
    Severity.CRITICAL: "\033[91m",  # Red
    Severity.HIGH: "\033[93m",  # Yellow
    Severity.MEDIUM: "\033[33m",  # Orange
    Severity.LOW: "\033[36m",  # Cyan
    Severity.INFO: "\033[37m",  # White
}
_RESET = "\033[0m"
_BOLD = "\033[1m"

# Claw pinch severity labels for human-facing output
_PINCH_LABELS = {
    Severity.CRITICAL: "HARD PINCH",
    Severity.HIGH: "HARD PINCH",
    Severity.MEDIUM: "SOFT PINCH",
    Severity.LOW: "NUDGE",
    Severity.INFO: "NUDGE",
}


def format_table(result: ScanResult, color: bool = True) -> str:
    """
    Format a ScanResult as a human-readable table with claw pinch branding.

    Deterministic: findings sorted by (rule_id, package, file, line).
    """
    B = _BOLD if color else ""
    R = _RESET if color else ""

    lines = []

    # Header
    lines.append(f"{B}🦞 PicoSentry{R}")
    lines.append(f"Target: {result.target}")
    lines.append(f"Engine: v{result.engine_version} | Corpus: v{result.corpus_version}")
    lines.append(f"Scan ID: {result.scan_id}")
    lines.append("")

    # Stats
    stats = result.stats
    lines.append(f"Packages scanned: {stats.packages_scanned}")
    lines.append(f"Files scanned:     {stats.files_scanned}")
    lines.append(f"Duration:          {stats.duration_ms}ms")
    if stats.rule_timings_ms:
        lines.append("")
        lines.append(f"{B}Rule Timings:{R}")
        for rule_id in sorted(stats.rule_timings_ms):
            ms = stats.rule_timings_ms[rule_id]
            count = stats.findings_by_rule.get(rule_id, 0)
            lines.append(f"  {rule_id:<18s} {ms:>5d}ms  ({count} findings)")
    lines.append("")

    # Severity summary with pinch labels
    if stats.findings_by_severity:
        lines.append(f"{B}Pinches by Severity:{R}")
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            count = stats.findings_by_severity.get(sev.value, 0)
            if count > 0:
                c = _COLORS.get(sev, "") if color else ""
                pinch = _PINCH_LABELS[sev]
                lines.append(f"  {c}{pinch:<12s}: {count}{R}")
        lines.append("")

    # Findings
    if not result.findings:
        lines.append(f"{B}No pinches. All clear. 🦞{R}")
    else:
        lines.append(f"{B}Pinches:{R}")
        lines.append("")

        sorted_findings = sorted(result.findings, key=lambda f: f.sort_key())

        for f in sorted_findings:
            c = _COLORS.get(f.severity, "") if color else ""
            pinch = _PINCH_LABELS[f.severity]

            lines.append(f"  {c}[{pinch}]{R} {f.rule_id} {f.package}")
            lines.append(f"    File: {f.file}" + (f":{f.line}" if f.line else ""))
            lines.append(f"    {f.message}")
            lines.append(f"    Evidence: {f.evidence[:120]}")
            lines.append(f"    Confidence: {f.confidence.value}")
            lines.append("")

    return "\n".join(lines)
