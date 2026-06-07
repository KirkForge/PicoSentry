
from __future__ import annotations

import os
from pathlib import Path

from picosentry.sandbox import __version__
from picosentry.sandbox.formatters.sarif import format_sarif
from picosentry.sandbox.l3.models import SandboxResult
from picosentry.sandbox.l4.models import AnalysisResult
from picosentry.sandbox.models import Severity


_DOME_LABELS = {
    Severity.CRITICAL: "HARD PINCH 🛡️",
    Severity.HIGH: "HARD PINCH 🛡️",
    Severity.MEDIUM: "SOFT PINCH",
    Severity.LOW: "NUDGE",
    Severity.INFO: "NUDGE",
}


def format_github(
    result: SandboxResult | AnalysisResult,
    sarif_path: str = "picodome-results.sarif",
) -> str:

    sarif_content = format_sarif(result)
    sarif_file = Path(sarif_path)
    sarif_file.write_text(sarif_content, encoding="utf-8")

    if isinstance(result, SandboxResult):
        return _l3_github(result, sarif_path)
    return _l4_github(result, sarif_path)


def _l3_github(result: SandboxResult, sarif_path: str) -> str:
    lines = []
    lines.append("## 🛡️ PicoDome — L3 Sandbox Results\n")


    verdict = result.overall_verdict.value
    icon = "✅" if verdict == "ALLOW" else "🚫"
    lines.append(f"**Verdict: {icon} {verdict}**\n")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| Command | `{' '.join(result.command)}` |")
    lines.append(f"| Policy | {result.policy_name or 'default'} |")
    lines.append(f"| Exit Code | {result.exit_code} |")
    lines.append(f"| Events | {len(result.events)} |")
    lines.append(f"| SARIF | `{sarif_path}` |")
    lines.append("")

    if result.events:
        lines.append("### Events\n")
        lines.append("| Rule | Verdict | Operation | Detail |")
        lines.append("|------|---------|-----------|--------|")
        for event in result.events[:50]:
            lines.append(f"| {event.rule_id} | {event.verdict.value} | {event.operation} | {event.detail[:80]} |")
        remaining = len(result.events) - 50
        if remaining > 0:
            lines.append(f"\n> ... and {remaining} more event(s)\n")

    summary = "\n".join(lines)
    _append_github_summary(summary)
    return summary


def _l4_github(result: AnalysisResult, sarif_path: str) -> str:
    lines = []
    lines.append("## 🛡️ PicoDome — L4 Behavioral Analysis\n")


    verdict = result.overall_verdict.value
    icon = "✅" if verdict == "CLEAN" else ("⚠️" if verdict == "SUSPICIOUS" else "🚫")

    if not result.findings:
        lines.append(f"**{icon} {verdict}** — All clear. Dome intact. 🛡️\n")
    else:
        lines.append(f"**{icon} {verdict}** — {len(result.findings)} finding(s)\n")


        lines.append("| Severity | Count | Label |")
        lines.append("|----------|-------|-------|")
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            count = result.stats.findings_by_severity.get(sev.value, 0)
            if count > 0:
                label = _DOME_LABELS.get(sev, sev.value)
                lines.append(f"| {sev.value} | {count} | {label} |")
        lines.append("")


        lines.append("### Findings\n")
        lines.append("| Rule | Severity | Message | Location |")
        lines.append("|------|----------|---------|----------|")
        for f in result.findings[:50]:
            lines.append(f"| {f.rule_id} | {f.severity.value} | {f.message[:80]} | {f.location or '—'} |")
        remaining = len(result.findings) - 50
        if remaining > 0:
            lines.append(f"\n> ... and {remaining} more finding(s)\n")


    lines.append("\n---\n")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| Engine | v{__version__} |")
    lines.append(f"| Target | `{result.target}` |")
    lines.append(f"| Findings | {len(result.findings)} |")
    lines.append(f"| SARIF | `{sarif_path}` |")

    summary = "\n".join(lines)
    _append_github_summary(summary)
    return summary


def _append_github_summary(summary: str) -> None:
    gh_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_summary:
        try:
            with open(gh_summary, "a", encoding="utf-8") as f:
                f.write(summary + "\n")
        except OSError:
            pass  # Non-fatal — summary still goes to stdout
