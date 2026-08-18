"""WO5.0.0-005: kill-chain escalation is scoped to the org that completed the run.

The completed-run subscriber must take org from Event.org_id — the publisher
(orchestrator) puts it on the event envelope, never in the payload dict.
Reading payload["org_id"] yielded None, and critical_chains(org_id=None)
matches EVERY tenant's events: one org's run escalated every org's chains.
"""

from __future__ import annotations

from picosentry._core.models import Confidence, Severity
from picosentry.serve.database.manager import db
from picosentry.serve.services.correlation import CorrelatedEvent, correlation_engine
from picosentry.serve.services.event_bus import event_bus


def _event(artifact: str, org: str) -> CorrelatedEvent:
    return CorrelatedEvent(
        artifact_id=artifact,
        layer="scan",
        rule_id="L2-TYPO-001",
        severity=Severity.CRITICAL,
        confidence=Confidence.EXACT,
        target="test-project",
        title="Typosquat detected",
        detail="Looks like legit-pkg",
        timestamp="2026-08-18T12:00:00+00:00",
        org_id=org,
        run_id="run-001",
    )


class TestKillChainEscalationTenancy:
    def test_org_a_completion_escalates_only_org_a_chains(self):
        artifact_a = "wo5-orga-pkg@1.0.0"
        artifact_b = "wo5-orgb-pkg@1.0.0"

        escalated: list[tuple[str, str | None]] = []

        def _record(chain):
            escalated.append((chain.artifact_id, chain.org_id))

        prev_persist = correlation_engine.PERSIST_ENABLED
        correlation_engine.PERSIST_ENABLED = False
        correlation_engine.on_chain_escalated(_record)
        correlation_engine.ingest(_event(artifact_a, "1"))
        correlation_engine.ingest(_event(artifact_b, "2"))

        try:
            # Publish exactly like the orchestrator publisher does: org on the
            # event envelope, NOT in the payload dict.
            event_bus.publish(
                "project.run.completed",
                {
                    "project_id": "picosentry",
                    "run_id": 1,
                    "status": "completed",
                    "duration": 1.0,
                    "exit_code": 0,
                    "intelligence_count": 0,
                },
                source="orchestrator",
                org_id="1",
            )

            # Only org A's chain escalated, stamped with org A. (Other tests
            # instantiate EnhancedOrchestrator, each adding a subscriber for
            # project.run.completed — so org A may fire more than once; the
            # tenancy invariant is that NO other org ever appears.)
            assert escalated
            assert {artifact for artifact, _ in escalated} == {artifact_a}
            assert {org for _, org in escalated} == {"1"}

            # Negative: no escalation alert stored org-less (org_id NULL) and
            # none referencing org B's artifact — the cross-tenant leak shape.
            leaked = db.execute(
                "SELECT id FROM alerts WHERE alert_type = 'chain_escalated' AND (org_id IS NULL OR project_id = ?)",
                (artifact_b,),
            )
            assert leaked == []
        finally:
            correlation_engine.PERSIST_ENABLED = prev_persist
            correlation_engine._escalation_callbacks.remove(_record)
            for artifact in (artifact_a, artifact_b):
                correlation_engine._events.pop(artifact, None)
                for key in [k for k in correlation_engine._chains if k[1] == artifact]:
                    del correlation_engine._chains[key]
            db.execute("DELETE FROM alerts WHERE project_id IN (?, ?)", (artifact_a, artifact_b))
