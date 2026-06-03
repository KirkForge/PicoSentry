"""ML context formatter — compact, token-budgeted output for LLM context.

Designed to be safe to inject into an agent's context without polluting
reasoning or causing hallucinated fixes. No narrative, no severity inflation.

Deterministic: same input = same output. Sorted keys, no timestamps.
"""

from __future__ import annotations

from picosentry.sandbox import __version__
from picosentry.sandbox.l3.models import SandboxResult
from picosentry.sandbox.l4.models import AnalysisResult
from picosentry.sandbox.models import Severity

# Dome-themed severity labels (compact for token efficiency)
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
    """
    Format a result as compact structured text for ML/LLM context.

    Token-budgeted — output is truncated if it exceeds budget.
    No narrative — the consumer formats findings.

    Args:
        result: SandboxResult or AnalysisResult to format.
        token_budget: Approximate token budget (1 token ≈ 4 chars).
    """
    if isinstance(result, SandboxResult):
        return _l3_ml_context(result, token_budget)
    return _l4_ml_context(result, token_budget)


def _l3_ml_context(result: SandboxResult, token_budget: int) -> str:
    """Format L3 sandbox result for ML context."""
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
        for event in result.events:
            lines.append(f"  - {event.rule_id}: {event.verdict.value} | {event.operation} | {event.detail}")
    else:
        lines.append("events: 0")

    output = "\n".join(lines)
    return _truncate_to_budget(output, token_budget)


def _l4_ml_context(result: AnalysisResult, token_budget: int) -> str:
    """Format L4 analysis result for ML context."""
    lines = [
        f"PICODOME L4 ANALYSIS | v{__version__}",
        f"target: {result.target}",
        f"verdict: {result.overall_verdict.value}",
        f"findings: {len(result.findings)}",
    ]

    if result.findings:
        # Group by severity
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
        for d in result.drift_results:
            lines.append(f"  baseline={d.baseline_name} score={d.score:.0%}")

    output = "\n".join(lines)
    return _truncate_to_budget(output, token_budget)


def _truncate_to_budget(text: str, token_budget: int) -> str:
    """Truncate text to approximately fit within a token budget.

    Uses rough heuristic: 1 token ≈ 4 characters.
    """
    max_chars = token_budget * 4
    if len(text) <= max_chars:
        return text

    truncated = text[: max_chars - 3] + "..."
    return truncated
