"""Tests for the cross-layer kill-chain correlation engine (Phase 1)."""

import pytest

from picosentry._core.models import Confidence, Severity
from picosentry.serve.services.correlation import (
    CorrelatedEvent,
    CorrelationEngine,
    KillChainPhase,
    KillChainTimeline,
    _confidence_from_str,
    _confidence_index,
    _severity_from_str,
    _severity_index,
    build_event_from_intel,
)

# ═══════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════


@pytest.fixture
def engine():
    """Fresh correlation engine for each test."""
    e = CorrelationEngine()
    yield e
    e.clear()


@pytest.fixture
def ts():
    """Fixed timestamp for deterministic tests."""
    return "2026-06-03T12:00:00+00:00"


@pytest.fixture
def sample_events(ts):
    """Sample events simulating a cross-layer attack chain on one artifact."""
    return [
        CorrelatedEvent(
            artifact_id="malicious-pkg@1.0.0",
            layer="scan",
            rule_id="L2-TYPO-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            target="test-project",
            title="Typosquat package detected",
            detail="malicious-pkg is a typosquat of legit-pkg",
            timestamp=ts,
            run_id="run-001",
        ),
        CorrelatedEvent(
            artifact_id="malicious-pkg@1.0.0",
            layer="scan",
            rule_id="L2-POST-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.EXACT,
            target="test-project",
            title="Malicious post-install script",
            detail="setup.py contains base64-encoded payload",
            timestamp=ts,
            run_id="run-001",
        ),
        CorrelatedEvent(
            artifact_id="malicious-pkg@1.0.0",
            layer="sandbox_l3",
            rule_id="L3-NET-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            target="test-project",
            title="Outbound connection to unknown IP",
            detail="Socket to 198.51.100.99:4444",
            timestamp=ts,
            run_id="run-001",
        ),
        CorrelatedEvent(
            artifact_id="malicious-pkg@1.0.0",
            layer="watch",
            rule_id="L5-PROMPT-002",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            target="test-project",
            title="Prompt injection detected in agent context",
            detail="Agent prompt contains 'ignore previous instructions' pattern",
            timestamp=ts,
            run_id="run-001",
        ),
    ]


@pytest.fixture
def single_layer_events(ts):
    """Events from only one layer — should produce low chain_score."""
    return [
        CorrelatedEvent(
            artifact_id="safe-pkg@2.0.0",
            layer="scan",
            rule_id="L2-PROV-001",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            target="test-project",
            title="Missing provenance",
            detail="Package has no SLSA provenance attestation",
            timestamp=ts,
            run_id="run-002",
        ),
        CorrelatedEvent(
            artifact_id="safe-pkg@2.0.0",
            layer="scan",
            rule_id="L2-PROV-001",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            target="test-project",
            title="Missing provenance (another file)",
            detail="Another file missing attestation",
            timestamp=ts,
            run_id="run-002",
        ),
    ]


# ═══════════════════════════════════════════════════════════════════════════
# Data Model Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestCorrelatedEvent:
    def test_frozen(self):
        event = CorrelatedEvent(
            artifact_id="pkg@1.0",
            layer="scan",
            rule_id="L2-TEST-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            target="proj",
            title="Test event",
            detail="Detail",
            timestamp="2026-01-01T00:00:00Z",
        )
        with pytest.raises(AttributeError):
            event.artifact_id = "other"

    def test_to_dict(self):
        event = CorrelatedEvent(
            artifact_id="pkg@1.0",
            layer="scan",
            rule_id="L2-TEST-001",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            target="proj",
            title="Test event",
            detail="Detail text",
            timestamp="2026-01-01T00:00:00Z",
            run_id="run-99",
        )
        d = event.to_dict()
        assert d["artifact_id"] == "pkg@1.0"
        assert d["layer"] == "scan"
        assert d["rule_id"] == "L2-TEST-001"
        assert d["severity"] == "HIGH"
        assert d["confidence"] == "EXACT"
        assert d["target"] == "proj"
        assert d["title"] == "Test event"
        assert d["detail"] == "Detail text"
        assert d["timestamp"] == "2026-01-01T00:00:00Z"
        assert d["run_id"] == "run-99"

    def test_default_run_id_is_none(self):
        event = CorrelatedEvent(
            artifact_id="pkg@1.0",
            layer="scan",
            rule_id="L2-TEST-001",
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            target="proj",
            title="Test",
            detail="Detail",
            timestamp="2026-01-01T00:00:00Z",
        )
        assert event.run_id is None


class TestKillChainTimeline:
    def test_to_dict(self, sample_events):
        timeline = KillChainTimeline(
            artifact_id="malicious-pkg@1.0.0",
            phases={"delivery": [sample_events[0]], "execution": [sample_events[1]]},
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            chain_score=0.85,
            narrative="Test narrative",
            related_targets=["test-project"],
        )
        d = timeline.to_dict()
        assert d["artifact_id"] == "malicious-pkg@1.0.0"
        assert d["chain_score"] == 0.85
        assert d["severity"] == "CRITICAL"
        assert d["confidence"] == "HIGH"
        assert d["narrative"] == "Test narrative"
        assert d["event_count"] == 2
        assert d["phase_count"] == 2
        assert "delivery" in d["phases"]
        assert "execution" in d["phases"]
        assert d["related_targets"] == ["test-project"]

    def test_empty_phases(self):
        timeline = KillChainTimeline(artifact_id="pkg@1.0")
        d = timeline.to_dict()
        assert d["event_count"] == 0
        assert d["phase_count"] == 0


# ═══════════════════════════════════════════════════════════════════════════
# KillChainPhase Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestKillChainPhase:
    @pytest.mark.parametrize(
        "phase,expected_value",
        [
            (KillChainPhase.RECONNAISSANCE, "reconnaissance"),
            (KillChainPhase.DELIVERY, "delivery"),
            (KillChainPhase.EXECUTION, "execution"),
            (KillChainPhase.PERSISTENCE, "persistence"),
            (KillChainPhase.C2, "c2"),
            (KillChainPhase.EXFILTRATION, "exfiltration"),
            (KillChainPhase.IMPACT, "impact"),
        ],
    )
    def test_enum_values(self, phase, expected_value):
        assert phase.value == expected_value

    def test_phase_weights_ordered(self):
        """Later phases should have higher weights."""
        phases = list(KillChainPhase)
        for i in range(len(phases) - 1):
            from picosentry.serve.services.correlation import PHASE_WEIGHTS

            assert PHASE_WEIGHTS[phases[i]] <= PHASE_WEIGHTS[phases[i + 1]]


# ═══════════════════════════════════════════════════════════════════════════
# CorrelationEngine Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestCorrelationEngineIngestion:
    def test_ingest_single_event(self, engine):
        event = CorrelatedEvent(
            artifact_id="pkg@1.0",
            layer="scan",
            rule_id="L2-TEST-001",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            target="proj",
            title="Test",
            detail="Detail",
            timestamp="2026-06-03T12:00:00Z",
        )
        engine.ingest(event)
        assert engine.all_artifact_ids() == ["pkg@1.0"]

    def test_ingest_many_atomic(self, engine, sample_events):
        engine.ingest_many(sample_events)
        assert engine.all_artifact_ids() == ["malicious-pkg@1.0.0"]
        raw = engine.kill_chain_raw("malicious-pkg@1.0.0")
        assert raw is not None
        assert len(raw) == 4

    def test_ingest_multiple_artifacts(self, engine, sample_events, single_layer_events):
        engine.ingest_many(sample_events)
        engine.ingest_many(single_layer_events)
        ids = engine.all_artifact_ids()
        assert sorted(ids) == ["malicious-pkg@1.0.0", "safe-pkg@2.0.0"]

    def test_fifo_eviction(self, engine):
        """When exceeding max per artifact, oldest events are evicted."""
        engine._max_events_per_artifact = 3
        for i in range(5):
            event = CorrelatedEvent(
                artifact_id="pkg@1.0",
                layer="scan",
                rule_id=f"L2-TEST-{i:03d}",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                target="proj",
                title=f"Event {i}",
                detail="",
                timestamp="2026-06-03T12:00:00Z",
            )
            engine.ingest(event)
        raw = engine.kill_chain_raw("pkg@1.0")
        assert raw is not None
        assert len(raw) == 3
        # Oldest 2 should be evicted — rule_id should start at L2-TEST-002
        assert raw[0].rule_id == "L2-TEST-002"
        assert raw[-1].rule_id == "L2-TEST-004"

    def test_ingest_does_not_raise(self, engine):
        """Ingesting should never raise, even with unusual data."""
        event = CorrelatedEvent(
            artifact_id="",
            layer="",
            rule_id="",
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            target="",
            title="",
            detail="",
            timestamp="",
        )
        engine.ingest(event)  # Should not raise


class TestCorrelationEngineKillChain:
    def test_kill_chain_multi_layer(self, engine, sample_events):
        """3-layer events should produce a high chain_score."""
        engine.ingest_many(sample_events)
        chain = engine.kill_chain("malicious-pkg@1.0.0")
        assert chain is not None
        assert chain.artifact_id == "malicious-pkg@1.0.0"
        assert chain.chain_score > 0.5
        assert chain.severity == Severity.CRITICAL
        assert len(chain.phases) >= 3  # delivery, execution, c2, recon
        assert "test-project" in chain.related_targets

    def test_kill_chain_single_layer(self, engine, single_layer_events):
        """Single-layer events should produce a low chain_score."""
        engine.ingest_many(single_layer_events)
        chain = engine.kill_chain("safe-pkg@2.0.0")
        assert chain is not None
        # Single layer, low severity → low score
        assert chain.chain_score <= 0.3
        assert chain.severity == Severity.LOW

    def test_kill_chain_none_for_missing(self, engine):
        """Querying nonexistent artifact should return None."""
        assert engine.kill_chain("nonexistent") is None

    def test_kill_chain_includes_narrative(self, engine, sample_events):
        engine.ingest_many(sample_events)
        chain = engine.kill_chain("malicious-pkg@1.0.0")
        assert chain is not None
        assert len(chain.narrative) > 0
        assert "malicious-pkg" in chain.narrative
        assert str(round(chain.chain_score, 2)) in chain.narrative

    def test_kill_chain_caching(self, engine, sample_events):
        """Kill chain should be invalidated (recomputed) after new events."""
        engine.ingest_many(sample_events)
        chain1 = engine.kill_chain("malicious-pkg@1.0.0")
        # Adding more events should invalidate cache — new chain differs
        new_event = CorrelatedEvent(
            artifact_id="malicious-pkg@1.0.0",
            layer="watch",
            rule_id="L6-OUTPUT-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            target="test-project",
            title="Output contains PII leak",
            detail="Credit card number detected in agent output",
            timestamp="2026-06-03T13:00:00Z",
            run_id="run-002",
        )
        engine.ingest(new_event)
        chain2 = engine.kill_chain("malicious-pkg@1.0.0")
        assert chain2 is not None
        # chain2 has 5 phases vs 4 before — exfiltration is new
        assert len(chain2.phases) == len(chain1.phases) + 1
        # chain2 should have a higher score due to additional CRITICAL event
        # in the exfiltration phase (weight 0.9)
        assert chain2.chain_score > chain1.chain_score


class TestCorrelationEngineCriticalChains:
    def test_critical_chains_above_threshold(self, engine, sample_events, single_layer_events):
        engine.ingest_many(sample_events)
        engine.ingest_many(single_layer_events)
        critical = engine.critical_chains(threshold=0.5)
        assert len(critical) >= 1
        assert critical[0].artifact_id == "malicious-pkg@1.0.0"

    def test_critical_chains_sorted(self, engine, sample_events, single_layer_events):
        engine.ingest_many(sample_events)
        engine.ingest_many(single_layer_events)
        critical = engine.critical_chains(threshold=0.0)
        for i in range(len(critical) - 1):
            assert critical[i].chain_score >= critical[i + 1].chain_score

    def test_critical_chains_empty(self, engine):
        assert engine.critical_chains() == []

    def test_critical_chains_no_match(self, engine, single_layer_events):
        engine.ingest_many(single_layer_events)
        high_threshold = engine.critical_chains(threshold=0.9)
        assert high_threshold == []


class TestCorrelationEngineAdmin:
    def test_clear(self, engine, sample_events):
        engine.ingest_many(sample_events)
        assert len(engine.all_artifact_ids()) == 1
        engine.clear()
        assert engine.all_artifact_ids() == []
        assert engine.stats()["artifacts"] == 0

    def test_stats(self, engine, sample_events):
        engine.ingest_many(sample_events)
        stats = engine.stats()
        assert stats["artifacts"] == 1
        assert stats["events"] == 4
        assert stats["avg_events_per_artifact"] == 4.0

    def test_stats_empty(self, engine):
        stats = engine.stats()
        assert stats["artifacts"] == 0
        assert stats["events"] == 0


class TestCorrelationEnginePhaseMapping:
    def test_rule_id_override_takes_precedence(self, engine):
        """Rule-specific phase mapping should override layer default."""
        event = CorrelatedEvent(
            artifact_id="pkg@1.0",
            layer="scan",
            rule_id="L2-TYPO-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            target="proj",
            title="Typosquat",
            detail="",
            timestamp="2026-06-03T12:00:00Z",
        )
        engine.ingest(event)
        chain = engine.kill_chain("pkg@1.0")
        assert chain is not None
        assert "delivery" in chain.phases  # L2-TYPO-001 maps to delivery

    def test_layer_fallback(self, engine):
        """Unmapped rule_id should fall back to layer-based phase."""
        event = CorrelatedEvent(
            artifact_id="pkg@1.0",
            layer="watch",
            rule_id="L5-UNKNOWN-999",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            target="proj",
            title="Unknown watch rule",
            detail="",
            timestamp="2026-06-03T12:00:00Z",
        )
        engine.ingest(event)
        chain = engine.kill_chain("pkg@1.0")
        assert chain is not None
        # watch layer maps to reconnaissance first
        assert "reconnaissance" in chain.phases


class TestCorrelationEngineEscalation:
    def test_on_chain_escalated_callback(self, engine, sample_events):
        received = []

        def callback(chain):
            received.append(chain.artifact_id)

        engine.on_chain_escalated(callback)
        engine._notify_escalated(
            KillChainTimeline(
                artifact_id="test-pkg",
                chain_score=0.9,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
            )
        )
        assert received == ["test-pkg"]

    def test_on_chain_escalated_error_does_not_raise(self, engine):
        """A failing callback should not propagate the exception."""

        def failing_callback(chain):
            raise RuntimeError("fail")

        engine.on_chain_escalated(failing_callback)
        # Should not raise
        engine._notify_escalated(
            KillChainTimeline(
                artifact_id="test-pkg",
                chain_score=0.9,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
            )
        )
        # No assertion needed — the test passes if no exception propagated

    def test_on_run_completed_no_crash(self, engine):
        """on_run_completed should never raise, even with no events."""
        engine.on_run_completed("test-project", run_id="run-001")
        # Should complete without error


# ═══════════════════════════════════════════════════════════════════════════
# Helper Function Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestBuildEventFromIntel:
    def test_valid_intel(self):
        intel = {
            "type": "threat_ip",
            "severity": "high",
            "data": {
                "matches": ["198.51.100.1"],
                "match_count": 1,
                "project": "test-proj",
            },
            "confidence": 0.8,
        }
        event = build_event_from_intel(intel, "test-proj", run_id="run-001", layer="scan")
        assert event is not None
        assert event.artifact_id == "test-proj"  # falls back to project_id
        assert event.layer == "scan"
        assert event.rule_id == "threat_ip"
        assert event.severity == Severity.HIGH
        assert event.confidence == Confidence.HIGH
        assert event.run_id == "run-001"

    def test_metrics_intel_skipped(self):
        intel = {
            "type": "metrics",
            "severity": "info",
            "data": {"some_metric": 42},
            "confidence": 1.0,
        }
        event = build_event_from_intel(intel, "test-proj")
        assert event is None

    def test_intel_with_snippet(self):
        intel = {
            "type": "failure_syntax_error",
            "severity": "critical",
            "data": {
                "project": "my-proj",
                "signature": "syntax_error",
                "description": "Python syntax error",
                "match_count": 1,
                "snippet": "File 'script.py', line 5: syntax error",
            },
            "confidence": 0.95,
        }
        event = build_event_from_intel(intel, "my-proj", run_id="run-002", layer="scan")
        assert event is not None
        assert event.rule_id == "failure_syntax_error"
        assert event.severity == Severity.CRITICAL
        assert event.confidence == Confidence.EXACT
        assert "Python syntax error" in event.detail
        assert "syntax error" in event.detail


class TestSeverityHelpers:
    @pytest.mark.parametrize(
        "severity,expected_index",
        [
            (Severity.CRITICAL, 0),
            (Severity.HIGH, 1),
            (Severity.MEDIUM, 2),
            (Severity.LOW, 3),
            (Severity.INFO, 4),
        ],
    )
    def test_severity_index(self, severity, expected_index):
        assert _severity_index(severity) == expected_index

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("critical", Severity.CRITICAL),
            ("HIGH", Severity.HIGH),
            ("Medium", Severity.MEDIUM),
            ("unknown", Severity.INFO),
        ],
    )
    def test_severity_from_str(self, text, expected):
        assert _severity_from_str(text) == expected

    @pytest.mark.parametrize(
        "confidence,expected_index",
        [
            (Confidence.EXACT, 0),
            (Confidence.HIGH, 1),
            (Confidence.MEDIUM, 2),
            (Confidence.LOW, 3),
        ],
    )
    def test_confidence_index(self, confidence, expected_index):
        assert _confidence_index(confidence) == expected_index

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("EXACT", Confidence.EXACT),
            ("high", Confidence.HIGH),
            ("unknown", Confidence.LOW),
        ],
    )
    def test_confidence_from_str(self, text, expected):
        assert _confidence_from_str(text) == expected

    @pytest.mark.parametrize(
        "value,expected",
        [
            (0.95, Confidence.EXACT),
            (0.8, Confidence.HIGH),
            (0.5, Confidence.MEDIUM),
            (0.3, Confidence.LOW),
            (0.9, Confidence.EXACT),
            (0.7, Confidence.HIGH),
            (0.4, Confidence.MEDIUM),
        ],
    )
    def test_confidence_from_float(self, value, expected):
        assert _confidence_from_str(value) == expected


# ═══════════════════════════════════════════════════════════════════════════
# Edge Cases
# ═══════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    def test_very_long_artifact_id(self, engine):
        """Very long artifact IDs should not cause issues."""
        long_id = "a" * 10_000
        event = CorrelatedEvent(
            artifact_id=long_id,
            layer="scan",
            rule_id="L2-TEST-001",
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            target="proj",
            title="Long ID",
            detail="",
            timestamp="2026-06-03T12:00:00Z",
        )
        engine.ingest(event)
        chain = engine.kill_chain(long_id)
        assert chain is not None
        assert chain.artifact_id == long_id

    def test_many_small_events(self, engine):
        """Handling 1000 small events should not crash."""
        for i in range(1000):
            event = CorrelatedEvent(
                artifact_id="busy-pkg@1.0",
                layer="scan",
                rule_id=f"L2-TEST-{i:04d}",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                target="proj",
                title=f"Event {i}",
                detail="x",
                timestamp="2026-06-03T12:00:00Z",
            )
            engine.ingest(event)
        chain = engine.kill_chain("busy-pkg@1.0")
        assert chain is not None
        d = chain.to_dict()
        assert d["event_count"] > 0

    def test_events_without_run_id(self, engine):
        """Events without run_id should still work."""
        event = CorrelatedEvent(
            artifact_id="pkg@1.0",
            layer="scan",
            rule_id="L2-TEST-001",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            target="proj",
            title="No run ID",
            detail="",
            timestamp="2026-06-03T12:00:00Z",
        )
        engine.ingest(event)
        chain = engine.kill_chain("pkg@1.0")
        assert chain is not None
        assert chain.to_dict()["event_count"] == 1

    def test_concurrent_ingestion_safety(self, engine, sample_events):
        """Multiple threads ingesting should not corrupt state."""
        import threading

        errors = []

        def ingest_batch():
            try:
                for _ in range(100):
                    engine.ingest_many(sample_events)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=ingest_batch) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        chain = engine.kill_chain("malicious-pkg@1.0.0")
        assert chain is not None
        assert chain.to_dict()["event_count"] > 0


class TestCorrelationEngineHardening:
    """Broad-exception sites must log the underlying reason, not silently swallow."""

    def test_failing_escalation_callback_is_logged(self, engine, caplog):
        import logging

        def failing_callback(chain):
            raise RuntimeError("callback boom")

        engine.on_chain_escalated(failing_callback)
        chain = KillChainTimeline(
            artifact_id="test-pkg",
            chain_score=0.9,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
        )

        with caplog.at_level(logging.ERROR, logger="picosentry.correlation"):
            engine._notify_escalated(chain)

        assert any("Escalation callback failed" in r.message for r in caplog.records)
        assert any(
            "callback boom" in r.message or (r.exc_info and "callback boom" in str(r.exc_info[1]))
            for r in caplog.records
        )

    def test_persistence_probe_failure_is_logged(self, monkeypatch, caplog):
        import logging
        from picosentry.serve.services.correlation import engine as engine_mod

        def _boom(*args, **kwargs):
            raise RuntimeError("no such table")

        monkeypatch.setattr(engine_mod.db, "execute", _boom)
        CorrelationEngine.PERSIST_ENABLED = True  # ensure flip to False is exercised

        with caplog.at_level(logging.DEBUG, logger="picosentry.correlation"):
            result = CorrelationEngine.enable_persistence_if_supported()

        assert result is False
        assert CorrelationEngine.PERSIST_ENABLED is False
        assert any("Correlation persistence not available" in r.message for r in caplog.records)


class TestAutoAnalysisRemoved:
    """WO5.0.0-008: the dead auto-analysis publish chain is deleted — an
    exploitable critical chain must not emit project.run.* events. A re-add
    must come with a real consumer that runs the downstream project on the
    artifact (the orchestrator run machinery takes no target today)."""

    def test_no_auto_analysis_events_published(self):
        from picosentry.serve.services.correlation import CorrelationEngine
        from picosentry.serve.services.event_bus import event_bus

        engine = CorrelationEngine()
        engine.ingest(
            CorrelatedEvent(
                artifact_id="wo5-auto@1.0.0",
                layer="sandbox_l3",
                rule_id="L3-NET-001",  # C2 — an exploitable phase
                severity=Severity.CRITICAL,
                confidence=Confidence.EXACT,
                target="proj",
                title="C2 beacon",
                detail="dns tunnel",
                timestamp="2026-08-18T12:00:00+00:00",
                org_id="1",
            )
        )
        event_bus.clear_history()

        engine.on_run_completed("picosentry", run_id="r", org_id="1")

        types = [e.type for e in event_bus.get_history()]
        assert "project.run.auto_analyze" not in types
        assert "project.run.requested" not in types
