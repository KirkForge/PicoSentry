"""Tests for cross-layer correlation persistence and deduplication."""

import pytest

from picosentry._core.models import Confidence, Severity
from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.services.correlation import CorrelatedEvent, CorrelationEngine
from picosentry.serve.services.correlation.persistence import _dedup_key


@pytest.fixture
def db_manager(tmp_path):
    """Fresh SQLite database manager with correlation schema applied."""
    db_path = tmp_path / "correlation_test.db"
    manager = DatabaseManager(db_path=db_path, backend="sqlite")
    yield manager
    manager.close()


@pytest.fixture
def engine(db_manager, monkeypatch):
    """Fresh engine with persistence enabled against the test DB."""
    # Ensure the module-level db singleton points at our test DB for the test.
    from picosentry.serve.database import manager as db_module

    monkeypatch.setattr(db_module, "db", db_manager)

    e = CorrelationEngine()
    e.PERSIST_ENABLED = True
    yield e
    e.clear()


@pytest.fixture
def sample_event():
    return CorrelatedEvent(
        artifact_id="pkg@1.0.0",
        layer="scan",
        rule_id="L2-TYPO-001",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        target="test-project",
        title="Typosquat detected",
        detail="Looks like legit-pkg",
        timestamp="2026-06-03T12:00:00+00:00",
        run_id="run-001",
    )


def _count_chains(engine) -> int:
    from picosentry.serve.database import manager as db_module

    row = db_module.db.execute_one("SELECT COUNT(*) AS c FROM correlation_chains")
    return row["c"] if row else 0


class TestCorrelationPersistenceRoundTrip:
    def test_persist_events_and_load(self, engine, sample_event):
        engine.ingest(sample_event)
        persisted = engine.persist_events()
        assert persisted == 1

        engine2 = CorrelationEngine()
        engine2.PERSIST_ENABLED = True
        loaded = engine2.load_events()
        assert loaded == 1

        raw = engine2.kill_chain_raw("pkg@1.0.0")
        assert raw is not None
        assert len(raw) == 1
        assert raw[0].rule_id == "L2-TYPO-001"

    def test_dedup_key_stable(self, sample_event):
        key1 = _dedup_key(sample_event)
        key2 = _dedup_key(sample_event)
        assert key1 == key2
        assert len(key1) == 16

    def test_duplicate_events_suppressed(self, engine, sample_event):
        engine.ingest_many([sample_event, sample_event])
        persisted = engine.persist_events()
        assert persisted == 1

    def test_different_timestamp_is_different_key(self, engine, sample_event):
        second = CorrelatedEvent(
            artifact_id=sample_event.artifact_id,
            layer=sample_event.layer,
            rule_id=sample_event.rule_id,
            severity=sample_event.severity,
            confidence=sample_event.confidence,
            target=sample_event.target,
            title=sample_event.title,
            detail=sample_event.detail,
            timestamp="2026-06-03T12:00:01+00:00",
            run_id=sample_event.run_id,
        )
        engine.ingest_many([sample_event, second])
        assert engine.persist_events() == 2


class TestCorrelationChainsCache:
    def test_persist_chain_cache_upsert(self, engine, sample_event):
        engine.ingest(sample_event)
        chain = engine.kill_chain("pkg@1.0.0")
        assert chain is not None

        engine.persist_chains_cache()
        assert _count_chains(engine) == 1

        # Recompute and persist again — should update, not insert a second row.
        chain2 = engine.kill_chain("pkg@1.0.0")
        engine.persist_chains_cache()
        assert _count_chains(engine) == 1

        from picosentry.serve.database import manager as db_module

        row = db_module.db.execute_one(
            "SELECT artifact_id, chain_score, event_count, phase_count FROM correlation_chains WHERE artifact_id = ?",
            ("pkg@1.0.0",),
        )
        assert row is not None
        assert row["event_count"] == 1
        assert row["phase_count"] == 1
        assert row["chain_score"] == chain2.chain_score


class TestCorrelationBackpressure:
    def test_rate_limit_drops_excess(self, engine, sample_event):
        engine._max_events_per_minute = 5

        events = [
            CorrelatedEvent(
                artifact_id=f"pkg{i}@1.0",
                layer="scan",
                rule_id=f"L2-TEST-{i:03d}",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                target="proj",
                title=f"Event {i}",
                detail="",
                timestamp=f"2026-06-03T12:00:{i:02d}+00:00",
            )
            for i in range(10)
        ]
        engine.ingest_many(events)
        assert engine.stats()["events"] == 5

    def test_rate_limit_resets_per_minute_bucket(self, engine, sample_event, monkeypatch):
        engine._max_events_per_minute = 2

        fake_time = {"now": 0.0}

        def fake_monotonic():
            return fake_time["now"]

        import time as time_module

        monkeypatch.setattr(time_module, "monotonic", fake_monotonic)

        events = [
            CorrelatedEvent(
                artifact_id=f"pkg{i}@1.0",
                layer="scan",
                rule_id=f"L2-TEST-{i:03d}",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                target="proj",
                title=f"Event {i}",
                detail="",
                timestamp=f"2026-06-03T12:00:{i:02d}+00:00",
            )
            for i in range(4)
        ]
        engine.ingest_many(events[:2])
        assert engine.stats()["events"] == 2

        fake_time["now"] += 60.0
        engine.ingest_many(events[2:])
        assert engine.stats()["events"] == 4


class TestCorrelationPersistenceExceptionNarrowing:
    """DB persistence boundaries must log expected errors and propagate bugs."""

    def test_persist_events_expected_db_error_is_skipped(self, engine, sample_event, monkeypatch):
        import sqlite3

        from picosentry.serve.database import manager as db_module

        engine.ingest(sample_event)
        calls = {"raise": True}

        orig_execute_insert = db_module.db.execute_insert

        def _failing_insert(sql, params):
            if calls["raise"]:
                calls["raise"] = False
                raise sqlite3.OperationalError("disk I/O error")
            return orig_execute_insert(sql, params)

        monkeypatch.setattr(db_module.db, "execute_insert", _failing_insert)
        # First event skipped, retry next event (none) not exercised; no exception.
        assert engine.persist_events() == 0

    def test_persist_events_unexpected_error_propagates(self, engine, sample_event, monkeypatch):
        from picosentry.serve.database import manager as db_module

        engine.ingest(sample_event)

        def _boom(*args, **kwargs):
            raise NameError("programmer mistake")

        monkeypatch.setattr(db_module.db, "execute_insert", _boom)

        with pytest.raises(NameError, match="programmer mistake"):
            engine.persist_events()

    def test_load_events_expected_db_error_returns_zero(self, engine, sample_event, caplog, monkeypatch):
        import logging
        import sqlite3

        from picosentry.serve.database import manager as db_module

        engine.ingest(sample_event)
        engine.persist_events()

        def _boom(*args, **kwargs):
            raise sqlite3.OperationalError("disk I/O error")

        monkeypatch.setattr(db_module.db, "execute", _boom)

        with caplog.at_level(logging.WARNING, logger="picosentry.correlation"):
            assert engine.load_events() == 0
        assert any("Failed to load correlation events" in r.message for r in caplog.records)

    def test_load_events_unexpected_error_propagates(self, engine, sample_event, monkeypatch):
        from picosentry.serve.database import manager as db_module

        engine.ingest(sample_event)
        engine.persist_events()

        def _boom(*args, **kwargs):
            raise NameError("programmer mistake")

        monkeypatch.setattr(db_module.db, "execute", _boom)

        with pytest.raises(NameError, match="programmer mistake"):
            engine.load_events()

    def test_persist_chains_expected_db_error_is_skipped(self, engine, sample_event, monkeypatch):
        import sqlite3

        from picosentry.serve.database import manager as db_module

        engine.ingest(sample_event)
        engine.kill_chain("pkg@1.0.0")

        def _boom(*args, **kwargs):
            raise sqlite3.OperationalError("disk I/O error")

        monkeypatch.setattr(db_module.db, "execute_insert", _boom)

        assert engine.persist_chains_cache() == 0

    def test_persist_chains_unexpected_error_propagates(self, engine, sample_event, monkeypatch):
        from picosentry.serve.database import manager as db_module

        engine.ingest(sample_event)
        engine.kill_chain("pkg@1.0.0")

        def _boom(*args, **kwargs):
            raise NameError("programmer mistake")

        monkeypatch.setattr(db_module.db, "execute_insert", _boom)

        with pytest.raises(NameError, match="programmer mistake"):
            engine.persist_chains_cache()
