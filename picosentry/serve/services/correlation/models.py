"""Kill-chain correlation data models, enum, and phase mapping tables.

Extracted in v2.1.0 (refactor) from ``picosentry/serve/services/correlation.py``.

Contains:

- :class:`KillChainPhase` — the kill-chain phase enum.
- :data:`PHASE_WEIGHTS`, :data:`SEVERITY_WEIGHTS` — score-computation tables.
- :data:`LAYER_PHASE_MAP`, :data:`RULE_PHASE_OVERRIDES` — event→phase mapping.
- :class:`CorrelatedEvent` — frozen dataclass for a single event.
- :class:`KillChainTimeline` — output dataclass for a correlated chain.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from picosentry._core.models import Confidence, Severity


class KillChainPhase(str, Enum):
    """Phases of the cyber kill chain, mapped from PicoSentry rule layers."""

    RECONNAISSANCE = "reconnaissance"
    DELIVERY = "delivery"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    C2 = "c2"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


# Phase progression weights — later phases score higher in chain_score
PHASE_WEIGHTS: dict[KillChainPhase, float] = {
    KillChainPhase.RECONNAISSANCE: 0.3,
    KillChainPhase.DELIVERY: 0.5,
    KillChainPhase.EXECUTION: 0.6,
    KillChainPhase.PERSISTENCE: 0.7,
    KillChainPhase.C2: 0.8,
    KillChainPhase.EXFILTRATION: 0.9,
    KillChainPhase.IMPACT: 1.0,
}

# Severity weights for score computation
SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.7,
    "MEDIUM": 0.4,
    "LOW": 0.2,
    "INFO": 0.05,
}

# Default phase mapping: rule_id prefix → kill-chain phases
# More specific rule_id overrides can be added
LAYER_PHASE_MAP: dict[str, list[KillChainPhase]] = {
    "scan": [
        KillChainPhase.DELIVERY,
        KillChainPhase.EXECUTION,
        KillChainPhase.PERSISTENCE,
    ],
    "sandbox_l3": [
        KillChainPhase.EXECUTION,
        KillChainPhase.C2,
    ],
    "sandbox_l4": [
        KillChainPhase.RECONNAISSANCE,
        KillChainPhase.C2,
        KillChainPhase.EXFILTRATION,
    ],
    "watch": [
        KillChainPhase.RECONNAISSANCE,
        KillChainPhase.IMPACT,
        KillChainPhase.EXFILTRATION,
    ],
}

# Specific rule_id → phase overrides (takes precedence over layer-based mapping)
RULE_PHASE_OVERRIDES: dict[str, KillChainPhase] = {
    # Scan: delivery-phase rules
    "L2-TYPO-001": KillChainPhase.DELIVERY,
    "L2-DEPC-001": KillChainPhase.DELIVERY,
    # Scan: execution-phase rules
    "L2-POST-001": KillChainPhase.EXECUTION,
    "L2-OBFS-001": KillChainPhase.EXECUTION,
    "L2-MAL-001": KillChainPhase.EXECUTION,
    "L2-POSTINSTALL-001": KillChainPhase.EXECUTION,
    # Scan: persistence-phase rules
    "L2-PROV-001": KillChainPhase.PERSISTENCE,
    # Sandbox: execution
    "L3-PROC-001": KillChainPhase.EXECUTION,
    "L3-PROC-002": KillChainPhase.EXECUTION,
    "L3-PROC-003": KillChainPhase.EXECUTION,
    # Sandbox: C2
    "L3-NET-001": KillChainPhase.C2,
    "L3-NET-002": KillChainPhase.C2,
    # Sandbox L4: reconnaissance
    "L4-DNS-001": KillChainPhase.RECONNAISSANCE,
    # Sandbox L4: exfiltration
    "L4-FILE-001": KillChainPhase.EXFILTRATION,
    # Watch: reconnaissance
    "L5-PROMPT-001": KillChainPhase.RECONNAISSANCE,
    # Watch: impact
    "L5-PROMPT-002": KillChainPhase.IMPACT,
    # Watch: exfiltration
    "L6-OUTPUT-001": KillChainPhase.EXFILTRATION,
}


@dataclass(frozen=True)
class CorrelatedEvent:
    """A single event from any PicoSentry layer, ready for correlation.

    Immutable by design. Each event represents one atomic finding or
    observation that can be correlated with others sharing the same
    artifact_id.
    """

    artifact_id: str
    """Package@version, globally unique (e.g. 'lodash@4.17.21')."""

    layer: str
    """Source layer: 'scan' | 'sandbox_l3' | 'sandbox_l4' | 'watch'."""

    rule_id: str
    """Detector rule ID, e.g. 'L2-POST-001', 'L4-NETEX-001'."""

    severity: Severity
    """Event severity from the canonical enum."""

    confidence: Confidence
    """Confidence from the canonical enum."""

    target: str
    """Scan target / project name / prompt session."""

    title: str
    """Human-readable one-liner for this event."""

    detail: str
    """Evidence / context as a string (JSON for complex data)."""

    timestamp: str
    """ISO 8601 UTC timestamp of when the event was observed."""

    run_id: str | None = None
    """Serve orchestrator run ID for traceability."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "layer": self.layer,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "target": self.target,
            "title": self.title,
            "detail": self.detail,
            "timestamp": self.timestamp,
            "run_id": self.run_id,
        }


@dataclass
class KillChainTimeline:
    """Correlated output — a chronology of related events forming an attack narrative."""

    artifact_id: str
    """The package under analysis."""

    phases: dict[str, list[CorrelatedEvent]] = field(default_factory=dict)
    """Kill-chain phase → events in that phase."""

    severity: Severity = Severity.INFO
    """Overall chain severity (max of all events)."""

    confidence: Confidence = Confidence.LOW
    """Overall chain confidence."""

    chain_score: float = 0.0
    """Composite score 0.0–1.0."""

    narrative: str = ""
    """AI-generated attack story (empty in Phase 1)."""

    related_targets: list[str] = field(default_factory=list)
    """Other targets in the same chain."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "chain_score": round(self.chain_score, 3),
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "narrative": self.narrative,
            "phases": {
                phase: [e.to_dict() for e in events]
                for phase, events in sorted(self.phases.items())
            },
            "related_targets": self.related_targets,
            "event_count": sum(len(events) for events in self.phases.values()),
            "phase_count": len(self.phases),
        }


__all__ = [
    "CorrelatedEvent",
    "KillChainPhase",
    "KillChainTimeline",
    "LAYER_PHASE_MAP",
    "PHASE_WEIGHTS",
    "RULE_PHASE_OVERRIDES",
    "SEVERITY_WEIGHTS",
]
