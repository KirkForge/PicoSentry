"""Rich attack-narrative generation for kill-chain timelines.

Extracted in v2.1.0 (refactor) from the
``_generate_narrative`` method of
:class:`~picosentry.serve.services.correlation.engine.CorrelationEngine`.

Implemented as a free function (no ``self``) so it can be unit-tested in
isolation and the engine file stays focused on orchestration. Inputs are
passed explicitly — the function is pure.
"""
from __future__ import annotations

from typing import Any

from picosentry._core.models import Confidence, Severity
from picosentry.serve.services.correlation.models import (
    CorrelatedEvent,
    KillChainPhase,
    PHASE_WEIGHTS,
    SEVERITY_WEIGHTS,
)

_PHASE_ORDER: list[KillChainPhase] = [
    KillChainPhase.RECONNAISSANCE,
    KillChainPhase.DELIVERY,
    KillChainPhase.EXECUTION,
    KillChainPhase.PERSISTENCE,
    KillChainPhase.C2,
    KillChainPhase.EXFILTRATION,
    KillChainPhase.IMPACT,
]

_LAYER_NAMES: dict[str, str] = {
    "scan": "Supply Chain Scan",
    "sandbox_l3": "L3 Runtime Sandbox",
    "sandbox_l4": "L4 Advanced Sandbox",
    "watch": "LLM Watch / Prompt Defense",
}


def generate_narrative(
    artifact_id: str,
    phase_events: dict[str, list[CorrelatedEvent]],
    chain_score: float,
    max_severity: Severity,
    max_confidence: Confidence,
    layers_observed: set[str],
) -> str:
    """Generate a rich attack narrative from the phase-event data.

    Produces a multi-paragraph story covering phase progression, layer
    correlation, severity assessment, and attack pattern synthesis.

    Args:
        artifact_id: The package@version under analysis.
        phase_events: Map of phase name (str) → list of events in that phase.
        chain_score: Composite chain score in [0.0, 1.0].
        max_severity: Highest severity observed across all events.
        max_confidence: Highest confidence observed across all events.
        layers_observed: Set of source layer names ("scan", "sandbox_l3", etc.).

    Returns:
        A multi-paragraph Markdown-formatted narrative string.
    """
    active_phases: list[str] = [
        p.value for p in _PHASE_ORDER if p.value in phase_events
    ]

    if not active_phases:
        return f"No kill-chain activity detected for '{artifact_id}'."

    parts: list[str] = []

    # ── Opening summary ──
    layer_labels = [
        _LAYER_NAMES.get(l, l) for l in sorted(layers_observed)
    ]
    severity_label = max_severity.value.title()
    confidence_label = max_confidence.value.title()

    parts.append(
        f"**Kill-Chain Analysis for '{artifact_id}':** "
        f"This artifact exhibits activity across {len(active_phases)} of 7 "
        f"kill-chain phases, with findings from {len(layer_labels)} detection "
        f"layer(s): {', '.join(layer_labels)}. "
        f"The overall chain score is {chain_score:.2f}/1.00, "
        f"rated **{severity_label} severity** with **{confidence_label} confidence**."
    )

    # ── Phase progression ──
    parts.append("**Phase Progression:**")
    for i, phase_name in enumerate(active_phases):
        try:
            phase = KillChainPhase(phase_name)
        except ValueError:
            continue

        weight = PHASE_WEIGHTS.get(phase, 0.5)
        phase_events_list = phase_events[phase_name]

        # Compute phase score
        max_sev_weight = 0.0
        max_sev_name = "INFO"
        event_descriptions: list[str] = []
        layers_in_phase: set[str] = set()
        for evt in phase_events_list:
            sev_weight = SEVERITY_WEIGHTS.get(evt.severity.value, 0.0)
            if sev_weight > max_sev_weight:
                max_sev_weight = sev_weight
                max_sev_name = evt.severity.value
            layers_in_phase.add(evt.layer)
            event_descriptions.append(
                f"{evt.rule_id} ({evt.severity.value}) from {evt.layer}: {evt.title}"
            )

        phase_sev = f"{max_sev_name} severity" if max_sev_name != "INFO" else "informational"
        progression = ""
        if weight < 0.4:
            progression = " (early-stage)"
        elif weight > 0.85:
            progression = " (late-stage — critical)"

        layer_tag = f" [{', '.join(sorted(layers_in_phase))}]" if len(layers_in_phase) > 1 else ""

        parts.append(
            f"  {i+1}. **{phase_name.replace('_', ' ').title()}**{layer_tag} — "
            f"{len(phase_events_list)} event(s) at {phase_sev}{progression}: "
            + "; ".join(event_descriptions[:3])
            + (f" (+{len(event_descriptions) - 3} more)" if len(event_descriptions) > 3 else "")
        )

    # ── Multi-layer correlation ──
    if len(layers_observed) >= 2:
        layers_by_phase: dict[str, set[str]] = {}
        for phase_name in active_phases:
            for e in phase_events[phase_name]:
                layers_by_phase.setdefault(phase_name, set()).add(e.layer)

        multi_layer_phases = [
            pn for pn, ls in layers_by_phase.items() if len(ls) >= 2
        ]

        if multi_layer_phases:
            parts.append(
                "**Cross-Layer Correlation:** "
                f"Corroborating evidence spans multiple detection layers "
                f"in {len(multi_layer_phases)} phase(s): "
                f"{', '.join(p.replace('_', ' ').title() for p in multi_layer_phases)}. "
                "This cross-layer corroboration significantly increases confidence "
                "in the assessed attack pattern."
            )

    # ── Chain score interpretation ──
    if chain_score >= 0.8:
        score_assessment = (
            "CRITICAL — This artifact shows a near-complete attack chain "
            "with activity spanning multiple phases and layers. "
            "Immediate investigation and remediation are strongly recommended."
        )
    elif chain_score >= 0.5:
        score_assessment = (
            "ELEVATED — Significant attack chain activity detected. "
            "The artifact exhibits a concerning pattern that warrants "
            "thorough investigation and likely remediation."
        )
    elif chain_score >= 0.3:
        score_assessment = (
            "MODERATE — Some attack indicators present but the chain is incomplete. "
            "Monitor for additional activity that could fill in missing phases."
        )
    else:
        score_assessment = (
            "LOW — Minimal kill-chain activity. "
            "The artifact shows isolated indicators without a clear attack narrative."
        )

    parts.append(f"**Assessment:** {score_assessment}")

    # ── Coverage summary ──
    covered = len(active_phases)
    total_phases = len(_PHASE_ORDER)
    phase_pct = (covered / total_phases) * 100
    total_events = sum(len(e) for e in phase_events.values())
    parts.append(
        f"**Coverage:** {covered}/{total_phases} phases ({phase_pct:.0f}%), "
        f"{total_events} total events across {len(layers_observed)} layer(s)."
    )

    return "\n\n".join(parts)


__all__ = ["generate_narrative"]
