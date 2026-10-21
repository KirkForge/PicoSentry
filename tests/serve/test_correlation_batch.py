"""WO8.0.0-104: list_chains / chains_summary must batch, not call kill_chain per artifact.

The router looped all_artifact_ids x kill_chain (O(N) lock acquisitions);
all_chains does one locked pass and populates the cache in one walk.
"""

from __future__ import annotations

import time

from picosentry._core.models import Confidence, Severity
from picosentry.serve.services.correlation import CorrelatedEvent, CorrelationEngine


def _make_event(artifact_id: str, layer: str = "scan", rule_id: str = "L2-TEST-001"):
    return CorrelatedEvent(
        artifact_id=artifact_id,
        layer=layer,
        rule_id=rule_id,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        target="proj",
        title="test",
        detail="",
        timestamp="2026-08-22T12:00:00+00:00",
    )


class TestAllChainsBatch:
    def test_all_chains_returns_one_per_artifact(self):
        engine = CorrelationEngine()
        engine.ingest(_make_event("pkg-a@1.0"))
        engine.ingest(_make_event("pkg-b@1.0"))
        chains = engine.all_chains()
        assert len(chains) == 2
        ids = {c.artifact_id for c in chains}
        assert ids == {"pkg-a@1.0", "pkg-b@1.0"}
        engine.clear()

    def test_all_chains_sorted_by_score_desc(self):
        engine = CorrelationEngine()
        engine.ingest(_make_event("low@1.0", "scan", "L2-PROV-001"))
        engine.ingest(_make_event("high@1.0", "sandbox_l3", "L3-NET-001"))
        chains = engine.all_chains()
        assert chains[0].chain_score >= chains[1].chain_score
        engine.clear()

    def test_all_chains_org_scoped(self):
        engine = CorrelationEngine()
        engine.ingest(
            CorrelatedEvent(
                artifact_id="org1-art@1.0",
                layer="scan",
                rule_id="L2-TEST-001",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                target="proj",
                title="test",
                detail="",
                timestamp="2026-08-22T12:00:00+00:00",
                org_id="1",
            )
        )
        engine.ingest(
            CorrelatedEvent(
                artifact_id="org2-art@1.0",
                layer="scan",
                rule_id="L2-TEST-001",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                target="proj",
                title="test",
                detail="",
                timestamp="2026-08-22T12:00:00+00:00",
                org_id="2",
            )
        )
        chains = engine.all_chains(org_id="2")
        assert len(chains) == 1
        assert chains[0].artifact_id == "org2-art@1.0"
        engine.clear()

    def test_all_chains_caches_results(self):
        engine = CorrelationEngine()
        engine.ingest(_make_event("cached@1.0"))
        first = engine.all_chains()
        second = engine.all_chains()
        assert first[0] is second[0], "second call should return cached timeline objects"
        engine.clear()

    def test_all_chains_1000_artifacts_under_500ms(self):
        engine = CorrelationEngine()
        for i in range(1000):
            engine.ingest(_make_event(f"pkg-{i:04d}@1.0"))

        # CPU time, not wall clock: under xdist load the runner deschedules
        # workers and wall-clock ceilings flake (run 39518904835, 3.11 leg,
        # 0.591s vs 0.5 — local wall AND cpu are ~0.045s). An algorithmic
        # regression burns CPU, so process_time keeps full teeth and loses
        # the free-core/machine-load assumption (WO7 lessons: gateway test).
        start = time.process_time()
        chains = engine.all_chains()
        elapsed = time.process_time() - start

        assert len(chains) == 1000
        assert elapsed < 0.5, f"all_chains with 1000 artifacts took {elapsed:.3f}s CPU (>500ms)"
        engine.clear()

    def test_critical_chains_uses_all_chains(self):
        engine = CorrelationEngine()
        engine.ingest(_make_event("low@1.0", "scan", "L2-PROV-001"))
        engine.ingest(
            CorrelatedEvent(
                artifact_id="high@1.0",
                layer="sandbox_l3",
                rule_id="L3-NET-001",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                target="proj",
                title="c2 beacon",
                detail="dns tunnel",
                timestamp="2026-08-22T12:00:00+00:00",
            )
        )
        critical = engine.critical_chains(threshold=0.5)
        assert all(c.chain_score >= 0.5 for c in critical)
        assert len(critical) == 1
        assert critical[0].artifact_id == "high@1.0"
        engine.clear()

    def test_chains_summary_uses_batch(self):
        engine = CorrelationEngine()
        engine.ingest(_make_event("pkg-a@1.0", "scan", "L2-TEST-001"))
        engine.ingest(_make_event("pkg-b@1.0", "sandbox_l3", "L3-NET-001"))
        summary = engine.chains_summary()
        assert summary["total_chains"] == 2
        assert summary["total_artifacts"] == 2
        assert summary["total_events"] == 2
        engine.clear()
