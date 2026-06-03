"""Table formatter for PicoDome results — human-readable terminal output.

Uses dome-themed severity labels (like PicoSentry's claw-pinch branding):
  CRITICAL/HIGH → HARD PINCH 🛡️
  MEDIUM         → SOFT PINCH
  LOW/INFO       → NUDGE
  Clean scan     → "All clear. Dome intact. 🛡️"
"""

from __future__ import annotations

from picosentry.sandbox.l3.models import SandboxResult, Verdict
from picosentry.sandbox.l4.models import AnalysisResult, BehavioralVerdict
from picosentry.sandbox.models import Severity

# Dome-themed severity labels for human-facing output
_DOME_LABELS = {
    Severity.CRITICAL: "HARD PINCH 🛡️",
    Severity.HIGH: "HARD PINCH 🛡️",
    Severity.MEDIUM: "SOFT PINCH",
    Severity.LOW: "NUDGE",
    Severity.INFO: "NUDGE",
}


def format_table(result: SandboxResult | AnalysisResult) -> str:
    """Format sandbox or analysis result as a human-readable table."""
    if isinstance(result, SandboxResult):
        return _l3_table(result)
    return _l4_table(result)


def _l3_table(result: SandboxResult) -> str:
    """Format L3 sandbox result as a table."""
    width = max(80, len(" ".join(result.command)) + 20)

    lines = [
        "╔" + "═" * (width - 2) + "╗",
        f"║ {'PICODOME — L3 SANDBOX':^{width - 4}} ║",
        "╠" + "═" * (width - 2) + "╣",
        f"║ {'Command:':<16} {' '.join(result.command):<{width - 20}} ║",
    ]

    if result.run_id:
        lines.append(f"║ {'Run ID:':<16} {result.run_id:<{width - 20}} ║")
    if result.timestamp:
        lines.append(f"║ {'Timestamp:':<16} {result.timestamp:<{width - 20}} ║")

    lines.append(f"║ {'Policy:':<16} {result.policy_name:<{width - 20}} ║")

    if result.duration_ms:
        lines.append(f"║ {'Duration:':<16} {result.duration_ms}ms{'':<{width - 23 - len(str(result.duration_ms))}} ║")

    lines.append(f"║ {'Exit Code:':<16} {result.exit_code:<{width - 20}} ║")

    verdict_icon = _verdict_icon(result.overall_verdict)
    verdict_text = result.overall_verdict.value
    verdict_pad = width - 23 - len(verdict_text)
    lines.append(f"║ {'Verdict:':<16} {verdict_icon} {verdict_text}{'':<{verdict_pad}} ║")

    if result.events:
        lines.append("╠" + "═" * (width - 2) + "╣")
        lines.append(f"║ {'EVENTS':^{width - 4}} ║")
        lines.append("╟" + "─" * (width - 2) + "╢")

        for event in result.events[:20]:
            icon = _verdict_icon(event.verdict)
            detail = event.detail[: width - 30] if len(event.detail) > width - 30 else event.detail
            lines.append(f"║ {icon} {event.rule_id:<16} {detail:<{width - 21}} ║")

        if len(result.events) > 20:
            lines.append(f"║ {'... and ' + str(len(result.events) - 20) + ' more events':^{width - 4}} ║")

    lines.append("╚" + "═" * (width - 2) + "╝")

    if result.stderr:
        lines.append("")
        lines.append("STDERR:")
        lines.append(result.stderr[:500])

    return "\n".join(lines)


def _l4_table(result: AnalysisResult) -> str:
    """Format L4 analysis result as a table."""
    width = 80

    verdict_icon = _behavioral_icon(result.overall_verdict)
    lines = [
        "╔" + "═" * (width - 2) + "╗",
        f"║ {'PICODOME — L4 BEHAVIORAL ANALYSIS':^{width - 4}} ║",
        "╠" + "═" * (width - 2) + "╣",
        f"║ {'Target:':<16} {result.target:<{width - 20}} ║",
        f"║ {'Verdict:':<16} {verdict_icon}"
        f" {result.overall_verdict.value}"
        f"{'':<{width - 26 - len(result.overall_verdict.value)}} ║",
    ]

    if result.stats.duration_ms:
        lines.append(
            f"║ {'Duration:':<16} {result.stats.duration_ms}ms{'':<{width - 20 - len(str(result.stats.duration_ms))}} ║"
        )

    # Severity summary with dome labels
    if result.stats.findings_by_severity:
        lines.append("╠" + "═" * (width - 2) + "╣")
        lines.append(f"║ {'PINCHES BY SEVERITY':^{width - 4}} ║")
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            count = result.stats.findings_by_severity.get(sev.value, 0)
            if count > 0:
                label = _DOME_LABELS.get(sev, sev.value)
                lines.append(f"║   {label:<20s} {count:>3} ║")

    if result.findings:
        lines.append("╠" + "═" * (width - 2) + "╣")
        lines.append(f"║ {'FINDINGS (' + str(len(result.findings)) + ')':^{width - 4}} ║")
        lines.append("╟" + "─" * (width - 2) + "╢")

        for finding in result.findings[:20]:
            label = _DOME_LABELS.get(finding.severity, finding.severity.value[:4])
            msg = finding.message[: width - 30] if len(finding.message) > width - 30 else finding.message
            lines.append(f"║ [{label:<16s}] {finding.rule_id:<10} {msg:<{width - 32}} ║")

        if len(result.findings) > 20:
            lines.append(f"║ {'... and ' + str(len(result.findings) - 20) + ' more findings':^{width - 4}} ║")
    else:
        lines.append("╠" + "═" * (width - 2) + "╣")
        lines.append(f"║ {'All clear. Dome intact. 🛡️':^{width - 4}} ║")

    if result.drift_results:
        lines.append("╠" + "═" * (width - 2) + "╣")
        lines.append(f"║ {'BASELINE DRIFT':^{width - 4}} ║")
        for drift in result.drift_results:
            lines.append(f"║   Baseline: {drift.baseline_name:<{width - 16}} ║")
            lines.append(f"║   Drift Score: {drift.score:.0%}{'':<{width - 19}} ║")

    lines.append("╚" + "═" * (width - 2) + "╝")
    return "\n".join(lines)


def _verdict_icon(verdict: Verdict) -> str:
    if verdict == Verdict.ALLOW:
        return "✅"
    if verdict == Verdict.DENY:
        return "🚫"
    if verdict == Verdict.KILL:
        return "💀"
    return "❓"  # type: ignore[unreachable]


def _behavioral_icon(verdict: BehavioralVerdict) -> str:
    if verdict == BehavioralVerdict.CLEAN:
        return "✅"
    if verdict == BehavioralVerdict.SUSPICIOUS:
        return "⚠️"
    if verdict == BehavioralVerdict.MALICIOUS:
        return "🚫"
    return "❓"  # type: ignore[unreachable]
