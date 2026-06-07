
import os
from pathlib import Path

from picosentry.scan.formatters.sarif import format_sarif
from picosentry.scan.formatters.table import _PINCH_LABELS
from picosentry.scan.models import ScanResult, Severity


def format_github(result: ScanResult, sarif_path: str = "sarif.json") -> str:

    sarif_content = format_sarif(result)
    sarif_file = Path(sarif_path)
    sarif_file.write_text(sarif_content, encoding="utf-8")


    lines = []
    lines.append("## 🦞 PicoSentry Scan Results\n")


    if not result.findings:
        lines.append("**No pinches. All clear.** 🦞\n")
    else:

        lines.append(f"**{len(result.findings)} finding(s)** in `{result.target}`\n")


        lines.append("| Severity | Count | Label |")
        lines.append("|----------|-------|-------|")

        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            count = result.stats.findings_by_severity.get(sev.value, 0)
            if count > 0:
                pinch = _PINCH_LABELS.get(sev, sev.value)
                lines.append(f"| {sev.value} | {count} | {pinch} |")

        lines.append("")


        lines.append("### Findings\n")
        lines.append("| Rule | Package | File | Severity | Message |")
        lines.append("|------|---------|------|----------|---------|")

        shown = result.findings[:50]
        for f in shown:
            lines.append(f"| {f.rule_id} | `{f.package}` | `{f.file}` | {f.severity.value} | {f.message} |")

        remaining = len(result.findings) - 50
        if remaining > 0:
            lines.append(f"\n> ... and {remaining} more finding(s)\n")


    lines.append("\n---\n")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| Engine | v{result.engine_version} |")
    lines.append(f"| Corpus | v{result.corpus_version} |")
    lines.append(f"| Scan ID | `{result.scan_id}` |")
    lines.append(f"| Packages | {result.stats.packages_scanned} |")
    lines.append(f"| Files | {result.stats.files_scanned} |")
    lines.append(f"| Duration | {result.stats.duration_ms}ms |")
    lines.append(f"| SARIF | `{sarif_path}` |")

    summary = "\n".join(lines)


    gh_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_summary:
        try:
            with open(gh_summary, "a", encoding="utf-8") as gh_file:
                gh_file.write(summary + "\n")
        except OSError:
            pass  # Non-fatal — summary still goes to stdout

    return summary
