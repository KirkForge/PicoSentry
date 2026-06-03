"""Cross-layer kill-chain correlation engine.

Correlates findings from scan, sandbox, and watch layers into per-artifact
kill-chain timelines. This is what turns a list of warnings into an attack
narrative — and creates the competitive moat that no other product has
(scan + runtime sandbox + LLM defense in one package).

Phase 1: core data model + in-memory storage + ingestion.
Phase 2: kill-chain scoring + query API.
Phase 3: enhanced narrative + dashboard + persistence.
Phase 4: alerting + cross-layer auto-analysis.
"""

from __future__ import annotations

import json
import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from picosentry._core.models import Confidence, Severity
from picosentry.serve.database.manager import db

logger = logging.getLogger("picoshogun.CorrelationEngine")

# ─── Kill-chain phase definitions ────────────────────────────────────────


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


# ─── Data models ─────────────────────────────────────────────────────────


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


# ─── CorrelationEngine ───────────────────────────────────────────────────


class CorrelationEngine:
    """Correlates events from all PicoSentry layers into kill-chain timelines.

    Phase 1 uses in-memory storage. Thread-safe for concurrent ingestion
    from multiple project runs.

    Note: Uses RLock (re-entrant) so internal methods like critical_chains()
    can call kill_chain() without deadlocking.
    """

    def __init__(self):
        self._lock = threading.RLock()
        # artifact_id -> list[CorrelatedEvent]
        self._events: dict[str, list[CorrelatedEvent]] = defaultdict(list)
        # artifact_id -> KillChainTimeline (cached/recomputed)
        self._chains: dict[str, KillChainTimeline] = {}
        # Maximum events kept per artifact (FIFO eviction)
        self._max_events_per_artifact = 1000
        # Subscribers for chain escalation
        self._escalation_callbacks: list[callable] = []

    # ── Ingestion ──────────────────────────────────────────────────────

    def ingest(self, event: CorrelatedEvent) -> None:
        """Store an event and mark its chain for recomputation."""
        with self._lock:
            events = self._events[event.artifact_id]
            events.append(event)
            # FIFO eviction
            if len(events) > self._max_events_per_artifact:
                self._events[event.artifact_id] = events[-self._max_events_per_artifact :]
            # Invalidate cached chain
            self._chains.pop(event.artifact_id, None)

        logger.debug(
            "Ingested event: %s | %s | %s | %s",
            event.artifact_id, event.layer, event.rule_id, event.severity.value,
        )

    def ingest_many(self, events: list[CorrelatedEvent]) -> None:
        """Ingest multiple events atomically (under one lock acquisition)."""
        with self._lock:
            for event in events:
                artifact_events = self._events[event.artifact_id]
                artifact_events.append(event)
                if len(artifact_events) > self._max_events_per_artifact:
                    self._events[event.artifact_id] = artifact_events[-self._max_events_per_artifact :]
                self._chains.pop(event.artifact_id, None)

        logger.debug("Ingested batch of %d events", len(events))

    # ── Queries ────────────────────────────────────────────────────────

    def kill_chain(self, artifact_id: str) -> KillChainTimeline | None:
        """Get the full kill-chain timeline for one artifact.

        Computes the timeline from all stored events if not cached.
        Returns None if no events exist for this artifact.
        """
        with self._lock:
            if artifact_id in self._chains:
                return self._chains[artifact_id]

            events = self._events.get(artifact_id)
            if not events:
                return None

            timeline = self._compute_timeline(artifact_id, events)
            self._chains[artifact_id] = timeline
            return timeline

    def kill_chain_raw(self, artifact_id: str) -> list[CorrelatedEvent] | None:
        """Get raw events for an artifact without computing timeline.

        Useful for direct inspection or external tooling.
        """
        with self._lock:
            events = self._events.get(artifact_id)
            return list(events) if events else None

    def critical_chains(self, threshold: float = 0.5) -> list[KillChainTimeline]:
        """Get chains above a score threshold, sorted descending.

        Args:
            threshold: Minimum chain_score (0.0–1.0) to include.

        Returns:
            List of KillChainTimeline objects sorted by chain_score descending.
        """
        with self._lock:
            results = []
            for artifact_id in list(self._events.keys()):
                chain = self.kill_chain(artifact_id)
                if chain and chain.chain_score >= threshold:
                    results.append(chain)

            results.sort(key=lambda c: c.chain_score, reverse=True)
            return results

    def all_artifact_ids(self) -> list[str]:
        """List all artifact IDs that have stored events."""
        with self._lock:
            return list(self._events.keys())

    # ── Event bus integration ───────────────────────────────────────────

    def on_run_completed(self, project_id: str, run_id: str | None = None) -> None:
        """Handle a project.run.completed event from the event bus.

        The orchestrator or event bus subscriber calls this method when a
        project run finishes. The engine correlates any events already
        ingested for the project's artifacts.

        Phase 4 enhancement: cross-layer auto-analysis. When critical chains
        are detected, an event is emitted to trigger deeper analysis at the
        next layer.

        Args:
            project_id: The project that completed.
            run_id: Optional orchestrator run ID for traceability.
        """
        # Check if any chain crossed the threshold
        critical = self.critical_chains(threshold=0.7)

        # Cross-layer auto-analysis trigger (Phase 4)
        for chain in critical:
            self._notify_escalated(chain)
            self._trigger_cross_layer_analysis(chain, project_id, run_id)

        # Persist if enabled
        if self.PERSIST_ENABLED and critical:
            self.persist_events()
            self.persist_chains_cache()

        logger.info(
            "Run completed: %s (run=%s) — %d chain(s) above 0.7 threshold",
            project_id, run_id, len(critical),
        )

    # ── Cross-layer auto-analysis (Phase 4) ───────────────────────────

    _AUTO_ANALYSIS_MAP: dict[str, list[str]] = {
        "picosentry": ["picodome"],        # scan CRITICAL → sandbox
        "picodome": ["picowatch"],          # sandbox CRITICAL → watch
        "picowatch": [],                     # watch is terminal
    }

    def _trigger_cross_layer_analysis(
        self,
        chain: KillChainTimeline,
        source_project_id: str,
        run_id: str | None = None,
    ) -> None:
        """Emit event bus signals to trigger deeper analysis at the next layer.

        When a critical chain is found from a source layer, this emits a
        project.run.auto_analyze event that the orchestrator can pick up
        to automatically schedule analysis at the next layer.

        For example: scan finds CRITICAL → auto-submit to sandbox for
        runtime analysis. Sandbox finds C2/exfiltration → auto-submit to
        watch for prompt-level defense.
        """
        from picosentry.serve.services.event_bus import event_bus

        downstream_projects = self._AUTO_ANALYSIS_MAP.get(source_project_id, [])
        if not downstream_projects:
            return

        # Only auto-analyze chains that have exploitable phases
        exploitable_phases = {"execution", "c2", "exfiltration", "impact"}
        has_exploitable = any(
            p in exploitable_phases for p in chain.phases
        )
        if not has_exploitable:
            return

        # Extract a sample target/command from first exploitable phase event
        sample_target = chain.artifact_id
        for phase_name, events in chain.phases.items():
            if phase_name in exploitable_phases and events:
                sample_target = events[0].target
                break

        for downstream in downstream_projects:
            logger.info(
                "Auto-analysis trigger: %s %s → %s (chain_score=%.2f)",
                source_project_id, chain.artifact_id,
                downstream, chain.chain_score,
            )

            event_bus.publish(
                "project.run.auto_analyze",
                {
                    "source_project": source_project_id,
                    "downstream_project": downstream,
                    "artifact_id": chain.artifact_id,
                    "target": sample_target,
                    "run_id": run_id,
                    "chain_score": chain.chain_score,
                    "severity": chain.severity.value,
                    "phase_summary": list(chain.phases.keys()),
                },
                source="correlation_engine",
                priority="high",
            )

    # ── Escalation ──────────────────────────────────────────────────────

    def on_chain_escalated(self, callback: callable) -> None:
        """Register a callback for when a chain crosses the critical threshold.

        The callback receives the KillChainTimeline as its only argument.
        """
        self._escalation_callbacks.append(callback)

    def _notify_escalated(self, chain: KillChainTimeline) -> None:
        """Notify all escalation subscribers."""
        for callback in self._escalation_callbacks:
            try:
                callback(chain)
            except Exception as e:
                logger.error("Escalation callback failed for %s: %s", chain.artifact_id, e)

    # ── Internal computation ────────────────────────────────────────────

    def _compute_timeline(
        self, artifact_id: str, events: list[CorrelatedEvent]
    ) -> KillChainTimeline:
        """Build a KillChainTimeline from stored events.

        Groups events by kill-chain phase, computes compound severity,
        confidence, and chain_score, then generates an attack narrative
        describing the full progression.
        """
        # Group by phase
        phase_events: dict[str, list[CorrelatedEvent]] = defaultdict(list)
        max_severity = Severity.INFO
        max_confidence = Confidence.LOW
        targets: set[str] = set()
        layers_observed: set[str] = set()

        for event in events:
            phase = self._phase_for_event(event)
            phase_events[phase.value].append(event)
            targets.add(event.target)
            layers_observed.add(event.layer)

            # Track max severity
            if _severity_index(event.severity) < _severity_index(max_severity):
                max_severity = event.severity

            # Track max confidence
            if _confidence_index(event.confidence) < _confidence_index(max_confidence):
                max_confidence = event.confidence

        # Compute chain_score
        chain_score = self._compute_chain_score(phase_events)

        # Generate enhanced narrative (Phase 3: rich attack story)
        narrative = self._generate_narrative(
            artifact_id, phase_events, chain_score, max_severity, max_confidence,
            layers_observed,
        )

        return KillChainTimeline(
            artifact_id=artifact_id,
            phases=dict(phase_events),
            severity=max_severity,
            confidence=max_confidence,
            chain_score=chain_score,
            narrative=narrative,
            related_targets=sorted(targets),
        )

    # ── Narrative generation (Phase 3+) ─────────────────────────────────

    def _generate_narrative(
        self,
        artifact_id: str,
        phase_events: dict[str, list[CorrelatedEvent]],
        chain_score: float,
        max_severity: Severity,
        max_confidence: Confidence,
        layers_observed: set[str],
    ) -> str:
        """Generate a rich attack narrative from the phase-event data.

        Produces a multi-paragraph story covering phase progression,
        layer correlation, severity assessment, and attack pattern
        synthesis.
        """
        phase_order = [
            KillChainPhase.RECONNAISSANCE,
            KillChainPhase.DELIVERY,
            KillChainPhase.EXECUTION,
            KillChainPhase.PERSISTENCE,
            KillChainPhase.C2,
            KillChainPhase.EXFILTRATION,
            KillChainPhase.IMPACT,
        ]

        active_phases: list[str] = [
            p.value for p in phase_order if p.value in phase_events
        ]

        if not active_phases:
            return f"No kill-chain activity detected for '{artifact_id}'."

        parts: list[str] = []

        # ── Opening summary ──
        layer_names = {
            "scan": "Supply Chain Scan",
            "sandbox_l3": "L3 Runtime Sandbox",
            "sandbox_l4": "L4 Advanced Sandbox",
            "watch": "LLM Watch / Prompt Defense",
        }
        layer_labels = [
            layer_names.get(l, l) for l in sorted(layers_observed)
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
            cross_layer_events = [
                e for phase_name in active_phases
                for e in phase_events[phase_name]
            ]
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
        total_phases = len(phase_order)
        phase_pct = (covered / total_phases) * 100
        total_events = sum(len(e) for e in phase_events.values())
        parts.append(
            f"**Coverage:** {covered}/{total_phases} phases ({phase_pct:.0f}%), "
            f"{total_events} total events across {len(layers_observed)} layer(s)."
        )

        return "\n\n".join(parts)

    def _phase_for_event(self, event: CorrelatedEvent) -> KillChainPhase:
        """Map a CorrelatedEvent to its kill-chain phase.

        Priority: specific rule_id override > layer-based mapping > default.
        """
        # Check rule_id override first
        if event.rule_id in RULE_PHASE_OVERRIDES:
            return RULE_PHASE_OVERRIDES[event.rule_id]

        # Check rule_id prefix overrides (e.g., L2-TYPO-* → delivery via L2 prefix)
        # Extract prefix up to second hyphen
        parts = event.rule_id.split("-", 2)
        if len(parts) >= 2:
            prefix = f"{parts[0]}-{parts[1]}"
            if prefix in RULE_PHASE_OVERRIDES:
                return RULE_PHASE_OVERRIDES[prefix]

        # Fall back to layer-based mapping
        layer_phases = LAYER_PHASE_MAP.get(event.layer, [])
        if layer_phases:
            # Use the first phase for the layer as default
            return layer_phases[0]

        return KillChainPhase.DELIVERY

    def _compute_chain_score(
        self, phase_events: dict[str, list[CorrelatedEvent]]
    ) -> float:
        """Compute composite chain_score from phase activity.

        score = sum(phase_score * phase_weight) / sum(phase_weight)

        Where phase_score = max event severity in that phase (weighted),
        and phase_weight = phase progression weight.
        """
        total_weighted = 0.0
        total_weight = 0.0

        for phase_name, events in phase_events.items():
            try:
                phase = KillChainPhase(phase_name)
            except ValueError:
                continue

            phase_weight = PHASE_WEIGHTS.get(phase, 0.5)

            # Phase score = max severity of any event in this phase
            max_sev_weight = 0.0
            for event in events:
                sev_weight = SEVERITY_WEIGHTS.get(event.severity.value, 0.0)
                if sev_weight > max_sev_weight:
                    max_sev_weight = sev_weight

            total_weighted += max_sev_weight * phase_weight
            total_weight += phase_weight

        if total_weight == 0:
            return 0.0

        return total_weighted / total_weight

    # ── Persistence (Phase 3+) ─────────────────────────────────────────

    PERSIST_ENABLED = False  # Set True after init if DB table exists

    def persist_events(self) -> int:
        """Persist all in-memory events to SQLite.

        Uses INSERT OR IGNORE with a hash-based idempotency key to
        avoid duplicates across restarts.

        Returns the number of events persisted.
        """
        from hashlib import sha256

        if not self.PERSIST_ENABLED:
            return 0

        count = 0
        with self._lock:
            for artifact_id, events in list(self._events.items()):
                for event in events:
                    # Deterministic dedup key
                    dedup_key = sha256(
                        f"{event.artifact_id}|{event.layer}|{event.rule_id}"
                        f"|{event.timestamp}".encode()
                    ).hexdigest()[:16]

                    try:
                        db.execute_insert("""
                            INSERT OR IGNORE INTO correlation_events
                            (dedup_key, artifact_id, layer, rule_id, severity,
                             confidence, target, title, detail, timestamp, run_id)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            dedup_key, event.artifact_id, event.layer,
                            event.rule_id, event.severity.value,
                            event.confidence.value, event.target,
                            event.title, event.detail, event.timestamp,
                            event.run_id,
                        ))
                        count += 1
                    except Exception as e:
                        logger.debug("Persist skip for %s/%s: %s",
                                     event.artifact_id, event.rule_id, e)

        if count:
            logger.info("Persisted %d correlation event(s) to DB", count)
        return count

    def load_events(self) -> int:
        """Load events from SQLite into memory on startup.

        Returns the number of events loaded.
        """
        if not self.PERSIST_ENABLED:
            return 0

        count = 0
        try:
            rows = db.execute("""
                SELECT artifact_id, layer, rule_id, severity, confidence,
                       target, title, detail, timestamp, run_id
                FROM correlation_events
                ORDER BY timestamp ASC
            """)

            for row in rows:
                event = CorrelatedEvent(
                    artifact_id=row["artifact_id"],
                    layer=row["layer"],
                    rule_id=row["rule_id"],
                    severity=_severity_from_str(row["severity"]),
                    confidence=_confidence_from_str(row["confidence"]),
                    target=row["target"],
                    title=row["title"],
                    detail=row["detail"],
                    timestamp=row["timestamp"],
                    run_id=row["run_id"],
                )
                # Bypass lock and FIFO for bulk load
                events = self._events[event.artifact_id]
                events.append(event)
                count += 1

            # Invalidate all cached chains on reload
            self._chains.clear()
            logger.info("Loaded %d correlation event(s) from DB", count)
        except Exception as e:
            logger.warning("Failed to load correlation events: %s", e)

        return count

    def persist_chains_cache(self) -> int:
        """Persist cached chain summaries to SQLite.

        Returns the number of chains persisted.
        """
        if not self.PERSIST_ENABLED:
            return 0

        count = 0
        with self._lock:
            for artifact_id, chain in list(self._chains.items()):
                try:
                    existing = db.execute_one(
                        "SELECT 1 FROM correlation_chains WHERE artifact_id = ?",
                        (artifact_id,),
                    )
                    if existing:
                        db.execute("""
                            UPDATE correlation_chains
                            SET chain_score = ?, severity = ?, confidence = ?,
                                narrative = ?, event_count = ?, phase_count = ?,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE artifact_id = ?
                        """, (
                            chain.chain_score, chain.severity.value,
                            chain.confidence.value, chain.narrative,
                            sum(len(e) for e in chain.phases.values()),
                            len(chain.phases),
                            artifact_id,
                        ))
                    else:
                        db.execute_insert("""
                            INSERT INTO correlation_chains
                            (artifact_id, chain_score, severity, confidence,
                             narrative, event_count, phase_count)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (
                            artifact_id, chain.chain_score,
                            chain.severity.value, chain.confidence.value,
                            chain.narrative,
                            sum(len(e) for e in chain.phases.values()),
                            len(chain.phases),
                        ))
                    count += 1
                except Exception as e:
                    logger.debug("Chain persist skip for %s: %s", artifact_id, e)

        if count:
            logger.info("Persisted %d chain(s) to DB", count)
        return count

    # ── Summary (Phase 3+) ──────────────────────────────────────────────

    def chains_summary(self) -> dict[str, Any]:
        """Get dashboard-ready summary of all active chains.

        Returns dict with total, critical, high, etc. counts, plus
        top_chains, layer_coverage, and statistics.
        """
        with self._lock:
            all_ids = list(self._events.keys())

        all_chains: list[KillChainTimeline] = []
        layers_used: set[str] = set()
        total_events = 0
        for artifact_id in all_ids:
            chain = self.kill_chain(artifact_id)
            if chain:
                all_chains.append(chain)
                for events in chain.phases.values():
                    for e in events:
                        layers_used.add(e.layer)
                total_events += sum(len(e) for e in chain.phases.values())

        # Count by severity tier
        critical_count = sum(
            1 for c in all_chains if c.chain_score >= 0.8
        )
        high_count = sum(
            1 for c in all_chains if 0.5 <= c.chain_score < 0.8
        )
        medium_count = sum(
            1 for c in all_chains if 0.3 <= c.chain_score < 0.5
        )
        low_count = sum(
            1 for c in all_chains if c.chain_score < 0.3
        )

        # Top chains
        all_chains.sort(key=lambda c: c.chain_score, reverse=True)
        top = [c.to_dict() for c in all_chains[:10]]

        # Layer coverage
        layer_names = {
            "scan": "Supply Chain Scan",
            "sandbox_l3": "L3 Runtime Sandbox",
            "sandbox_l4": "L4 Advanced Sandbox",
            "watch": "LLM Watch / Prompt Defense",
        }
        layer_coverage = [
            {"layer": l, "label": layer_names.get(l, l)}
            for l in sorted(layers_used)
        ]

        # Phase histogram
        phase_order = [
            "reconnaissance", "delivery", "execution", "persistence",
            "c2", "exfiltration", "impact",
        ]
        phase_counts: dict[str, int] = {}
        for phase_name in phase_order:
            phase_counts[phase_name] = 0
        for chain in all_chains:
            for phase_name in chain.phases:
                if phase_name in phase_counts:
                    phase_counts[phase_name] += 1

        avg_score = (
            round(sum(c.chain_score for c in all_chains) / len(all_chains), 3)
            if all_chains else 0.0
        )

        return {
            "total_chains": len(all_chains),
            "total_events": total_events,
            "total_artifacts": len(all_ids),
            "layers_active": len(layers_used),
            "layer_coverage": layer_coverage,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "avg_chain_score": avg_score,
            "phase_distribution": phase_counts,
            "top_chains": top,
        }

    # ── Administrative ──────────────────────────────────────────────────

    def clear(self) -> None:
        """Clear all stored events and cached chains."""
        with self._lock:
            self._events.clear()
            self._chains.clear()
        logger.info("CorrelationEngine: cleared all events")

    def stats(self) -> dict[str, Any]:
        """Get engine statistics."""
        with self._lock:
            artifact_count = len(self._events)
            event_count = sum(len(events) for events in self._events.values())
            chain_count = len(self._chains)

        return {
            "artifacts": artifact_count,
            "events": event_count,
            "cached_chains": chain_count,
            "avg_events_per_artifact": round(event_count / artifact_count, 1) if artifact_count else 0.0,
        }


# ── Helper utilities ─────────────────────────────────────────────────────


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


# ── Global instance ──────────────────────────────────────────────────────

correlation_engine = CorrelationEngine()