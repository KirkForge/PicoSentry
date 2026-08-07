from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from picosentry import __version__
from picosentry._core.models import Severity

if TYPE_CHECKING:
    from picosentry.scan.models import ScanResult

_SEVERITY_SORT = {s.value: i for i, s in enumerate(Severity)}


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("[", "\\[").replace("\n", " ")


def _format_evidence_table(evidence: dict[str, Any]) -> list[str]:
    items = evidence.get("evidence", [])
    if not items:
        return []
    lines = [
        "",
        "## Behavioral Evidence",
        "",
        "| Type | Detail | Trigger |",
        "|------|--------|---------|",
    ]
    for item in items:
        lines.append(f"| {item.get('type', '')} | {item.get('detail', '')} | {item.get('trigger', '')} |")
    return lines


@dataclass
class MarkdownFormatter:
    result: ScanResult

    def format(self) -> str:
        lines: list[str] = []
        lines.append("## PicoSentry Security Scan")
        lines.append("")

        if not self.result.findings:
            lines.append("No findings. Dependencies appear safe.")
        else:
            by_sev: dict[str, int] = {}
            for f in self.result.findings:
                by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            parts: list[str] = []
            for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
                c = by_sev.get(sev.value, 0)
                if c:
                    parts.append(f"{c} {sev.value}")
            lines.append(f"Found {len(self.result.findings)} findings ({', '.join(parts)})")
            lines.append("")
            lines.append("| Severity | Rule | Package | File | Message |")
            lines.append("|----------|------|---------|------|---------|")
            for f in sorted(
                self.result.findings,
                key=lambda f: (
                    _SEVERITY_SORT.get(f.severity.value, 99),
                    f.sort_key(),
                ),
            ):
                severity = _md_escape(f.severity.value)
                rule = _md_escape(f.rule_id)
                package = _md_escape(f.package)
                file_ = _md_escape(f.file)
                message = _md_escape(f.message)
                lines.append(f"| {severity} | {rule} | {package} | {file_} | {message} |")

        if self.result.behavioral_evidence:
            lines.extend(_format_evidence_table(self.result.behavioral_evidence))

        lines.append("")
        dur = self.result.stats.duration_ms / 1000 if self.result.stats.duration_ms else 0
        ver = self.result.engine_version or __version__
        lines.append(f"*Scan completed in {dur:.1f}s — PicoSentry v{ver}*")
        return "\n".join(lines)


def format_markdown(result: ScanResult) -> str:
    return MarkdownFormatter(result).format()
