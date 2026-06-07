"""String↔enum conversion helpers + build_event_from_intel.

Extracted in v2.1.0 (refactor) from ``picosentry/serve/services/correlation.py``.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from picosentry._core.models import Confidence, Severity
from picosentry.serve.services.correlation.models import CorrelatedEvent


def _severity_index(severity: Severity) -> int:
    """Lower index = more severe."""
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    try:
        return order.index(severity.value)
    except ValueError:
        return len(order) - 1


def _confidence_index(confidence: Confidence) -> int:
    """Lower index = more confident."""
    order = ["EXACT", "HIGH", "MEDIUM", "LOW"]
    try:
        return order.index(confidence.value)
    except ValueError:
        return len(order) - 1


def _severity_from_str(value: str) -> Severity:
    """Parse a severity string into a Severity enum, case-insensitively."""
    try:
        return Severity(value.upper())
    except ValueError:
        return Severity.INFO


def _confidence_from_str(value: str | float) -> Confidence:
    """Parse a confidence string or float into a Confidence enum."""
    if isinstance(value, (int, float)):
        if value >= 0.9:
            return Confidence.EXACT
        if value >= 0.7:
            return Confidence.HIGH
        if value >= 0.4:
            return Confidence.MEDIUM
        return Confidence.LOW
    try:
        return Confidence(value.upper())
    except ValueError:
        return Confidence.LOW


def build_event_from_intel(
    intel: dict[str, Any],
    project_id: str,
    run_id: str | None = None,
    layer: str = "scan",
) -> CorrelatedEvent | None:
    """Build a CorrelatedEvent from an IntelligenceEngine intel dict.

    Args:
        intel: Intelligence dict from IntelligenceEngine.extract_from_output().
        project_id: Source project identifier.
        run_id: Optional orchestrator run ID.
        layer: Source layer ('scan', 'sandbox_l3', 'sandbox_l4', 'watch').

    Returns:
        CorrelatedEvent if the intel dict is well-formed, else None.
    """
    intel_type = intel.get("type", "")
    severity_str = intel.get("severity", "info")
    intel_data = intel.get("data", {})
    confidence_val = intel.get("confidence", 0.5)

    # Skip metrics and other non-finding intel types
    if intel_type in ("metrics",):
        return None

    # Build artifact_id from project or data fields
    project = intel_data.get("project", project_id)
    artifact_id = intel_data.get("package", project)

    detail_parts = []
    matches = intel_data.get("matches", [])
    if matches:
        detail_parts.append(f"Matches: {', '.join(matches[:5])}")
    snippet = intel_data.get("snippet", "")
    if snippet:
        detail_parts.append(f"Snippet: {snippet}")
    description = intel_data.get("description", "")
    if description:
        detail_parts.append(description)
    match_count = intel_data.get("match_count", 0)
    if match_count:
        detail_parts.append(f"Match count: {match_count}")

    return CorrelatedEvent(
        artifact_id=artifact_id,
        layer=layer,
        rule_id=intel_type,
        severity=_severity_from_str(severity_str),
        confidence=_confidence_from_str(confidence_val),
        target=project_id,
        title=intel_type.replace("_", " ").title(),
        detail=" | ".join(detail_parts) if detail_parts else str(intel_data),
        timestamp=datetime.now(timezone.utc).isoformat(),
        run_id=run_id,
    )


__all__ = [
    "_confidence_from_str",
    "_confidence_index",
    "_severity_from_str",
    "_severity_index",
    "build_event_from_intel",
]
