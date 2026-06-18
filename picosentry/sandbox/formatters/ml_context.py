
from __future__ import annotations

from picosentry.sandbox import __version__
from picosentry.sandbox.l3.models import SandboxResult
from picosentry.sandbox.l4.models import AnalysisResult
from picosentry.sandbox.models import Severity


_DOME_LABELS = {
    Severity.CRITICAL: "HARD PINCH",
    Severity.HIGH: "HARD PINCH",
    Severity.MEDIUM: "SOFT PINCH",
    Severity.LOW: "NUDGE",
    Severity.INFO: "NUDGE",
}


def format_ml_context(
    result: SandboxResult | AnalysisResult,
    token_budget: int = 4096,
) -> str:
    if isinstance(result, SandboxResult):
        return _l3_ml_context(result, token_budget)
    return _l4_ml_context(result, token_budget)


def _l3_ml_context(result: SandboxResult, token_budget: int) -> str:
    lines = [
        f"PICODOME L3 SANDBOX | v{__version__}",
        f"command: {' '.join(result.command)}",
        f"verdict: {result.overall_verdict.value}",
        f"exit_code: {result.exit_code}",
    ]

    if result.policy_name:
        lines.append(f"policy: {result.policy_name}")

    if result.events:
        lines.append(f"events: {len(result.events)}")
        lines.extend(
            f"  - {event.rule_id}: {event.verdict.value} | {event.operation} | {event.detail}"
            for event in result.events
        )
    else:
        lines.append("events: 0")

    output = "\n".join(lines)
    return _truncate_to_budget(output, token_budget)


def _l4_ml_context(result: AnalysisResult, token_budget: int) -> str:
    lines = [
        f"PICODOME L4 ANALYSIS | v{__version__}",
        f"target: {result.target}",
        f"verdict: {result.overall_verdict.value}",
        f"findings: {len(result.findings)}",
    ]

    if result.findings:

        by_severity: dict = {}
        for f in result.findings:
            sev = f.severity.value
            label = _DOME_LABELS.get(f.severity, sev)
            if label not in by_severity:
                by_severity[label] = []
            by_severity[label].append(f)

        for label in ("HARD PINCH", "SOFT PINCH", "NUDGE"):
            findings = by_severity.get(label, [])
            if findings:
                lines.append(f"\n{label} ({len(findings)}):")
                for f in findings:
                    lines.append(f"  [{f.rule_id}] {f.message}")
                    if f.location:
                        lines.append(f"    at: {f.location}")
    else:
        lines.append("\nAll clear. Dome intact.")

    if result.drift_results:
        lines.append(f"\ndrift: {len(result.drift_results)}")
        lines.extend(
            f"  baseline={d.baseline_name} score={d.score:.0%}"
            for d in result.drift_results
        )

    output = "\n".join(lines)
    return _truncate_to_budget(output, token_budget)


def _truncate_to_budget(text: str, token_budget: int) -> str:
    max_chars = token_budget * 4
    if len(text) <= max_chars:
        return text

    return text[: max_chars - 3] + "..."
