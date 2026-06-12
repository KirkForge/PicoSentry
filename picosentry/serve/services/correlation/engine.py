from __future__ import annotations

import logging
import threading
from collections import defaultdict
from typing import Any, ClassVar
from collections.abc import Callable

from picosentry._core.models import Confidence, Severity
from picosentry.serve.services.correlation.helpers import (
    _confidence_index,
    _severity_index,
)
from picosentry.serve.services.correlation.models import (
    CorrelatedEvent,
    KillChainPhase,
    KillChainTimeline,
    LAYER_PHASE_MAP,
    PHASE_WEIGHTS,
    RULE_PHASE_OVERRIDES,
    SEVERITY_WEIGHTS,
)
from picosentry.serve.services.correlation.narrative import generate_narrative
from picosentry.serve.services.correlation.persistence import (
    _load_events_impl,
    _persist_chains_cache_impl,
    _persist_events_impl,
)

logger = logging.getLogger("picosentry.correlation")


class CorrelationEngine:


    PERSIST_ENABLED: ClassVar[bool] = False

    def __init__(self):
        self._lock = threading.RLock()

        self._events: dict[str, list[CorrelatedEvent]] = defaultdict(list)

        self._chains: dict[str, KillChainTimeline] = {}

        self._max_events_per_artifact = 1000

        self._escalation_callbacks: list[Callable[[KillChainTimeline], None]] = []


    def ingest(self, event: CorrelatedEvent) -> None:
        with self._lock:
            events = self._events[event.artifact_id]
            events.append(event)

            if len(events) > self._max_events_per_artifact:
                self._events[event.artifact_id] = events[-self._max_events_per_artifact :]

            self._chains.pop(event.artifact_id, None)

        logger.debug(
            "Ingested event: %s | %s | %s | %s",
            event.artifact_id, event.layer, event.rule_id, event.severity.value,
        )

    def ingest_many(self, events: list[CorrelatedEvent]) -> None:
        with self._lock:
            for event in events:
                artifact_events = self._events[event.artifact_id]
                artifact_events.append(event)
                if len(artifact_events) > self._max_events_per_artifact:
                    self._events[event.artifact_id] = artifact_events[-self._max_events_per_artifact :]
                self._chains.pop(event.artifact_id, None)

        logger.debug("Ingested batch of %d events", len(events))


    def kill_chain(self, artifact_id: str) -> KillChainTimeline | None:
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
        with self._lock:
            events = self._events.get(artifact_id)
            return list(events) if events else None

    def critical_chains(self, threshold: float = 0.5) -> list[KillChainTimeline]:
        with self._lock:
            results = []
            for artifact_id in list(self._events.keys()):
                chain = self.kill_chain(artifact_id)
                if chain and chain.chain_score >= threshold:
                    results.append(chain)

            results.sort(key=lambda c: c.chain_score, reverse=True)
            return results

    def all_artifact_ids(self) -> list[str]:
        with self._lock:
            return list(self._events.keys())


    def on_run_completed(self, project_id: str, run_id: str | None = None) -> None:

        critical = self.critical_chains(threshold=0.7)


        for chain in critical:
            self._notify_escalated(chain)
            self._trigger_cross_layer_analysis(chain, project_id, run_id)


        if self.PERSIST_ENABLED and critical:
            self.persist_events()
            self.persist_chains_cache()

        logger.info(
            "Run completed: %s (run=%s) — %d chain(s) above 0.7 threshold",
            project_id, run_id, len(critical),
        )


    _AUTO_ANALYSIS_MAP: ClassVar[dict[str, list[str]]] = {
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
        from picosentry.serve.services.event_bus import event_bus

        downstream_projects = self._AUTO_ANALYSIS_MAP.get(source_project_id, [])
        if not downstream_projects:
            return


        exploitable_phases = {"execution", "c2", "exfiltration", "impact"}
        has_exploitable = any(
            p in exploitable_phases for p in chain.phases
        )
        if not has_exploitable:
            return


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
                },
            )

    def on_chain_escalated(self, callback: Callable[[KillChainTimeline], None]) -> None:
        self._escalation_callbacks.append(callback)

    def _notify_escalated(self, chain: KillChainTimeline) -> None:
        for callback in self._escalation_callbacks:
            try:
                callback(chain)
            except Exception as e:
                logger.error("Escalation callback failed for %s: %s", chain.artifact_id, e)


    def _compute_timeline(
        self, artifact_id: str, events: list[CorrelatedEvent]
    ) -> KillChainTimeline:

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


            if _severity_index(event.severity) < _severity_index(max_severity):
                max_severity = event.severity


            if _confidence_index(event.confidence) < _confidence_index(max_confidence):
                max_confidence = event.confidence


        chain_score = self._compute_chain_score(phase_events)


        narrative = generate_narrative(
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

    def _phase_for_event(self, event: CorrelatedEvent) -> KillChainPhase:

        if event.rule_id in RULE_PHASE_OVERRIDES:
            return RULE_PHASE_OVERRIDES[event.rule_id]


        parts = event.rule_id.split("-", 2)
        if len(parts) >= 2:
            prefix = f"{parts[0]}-{parts[1]}"
            if prefix in RULE_PHASE_OVERRIDES:
                return RULE_PHASE_OVERRIDES[prefix]


        layer_phases = LAYER_PHASE_MAP.get(event.layer, [])
        if layer_phases:

            return layer_phases[0]

        return KillChainPhase.DELIVERY

    def _compute_chain_score(
        self, phase_events: dict[str, list[CorrelatedEvent]]
    ) -> float:
        total_weighted = 0.0
        total_weight = 0.0

        for phase_name, events in phase_events.items():
            try:
                phase = KillChainPhase(phase_name)
            except ValueError:
                continue

            phase_weight = PHASE_WEIGHTS.get(phase, 0.5)


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


    def persist_events(self) -> int:
        return _persist_events_impl(self)

    def load_events(self) -> int:
        return _load_events_impl(self)

    def persist_chains_cache(self) -> int:
        return _persist_chains_cache_impl(self)


    def chains_summary(self) -> dict[str, Any]:
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


        all_chains.sort(key=lambda c: c.chain_score, reverse=True)
        top = [c.to_dict() for c in all_chains[:10]]


        layer_names = {
            "scan": "Supply Chain Scan",
            "sandbox_l3": "L3 Runtime Sandbox",
            "sandbox_l4": "L4 Advanced Sandbox",
            "watch": "LLM Watch / Prompt Defense",
        }
        layer_coverage = [
            {"layer": layer, "label": layer_names.get(layer, layer)}
            for layer in sorted(layers_used)
        ]


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


    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._chains.clear()
        logger.info("CorrelationEngine: cleared all events")

    def stats(self) -> dict[str, Any]:
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


__all__ = ["CorrelationEngine"]
