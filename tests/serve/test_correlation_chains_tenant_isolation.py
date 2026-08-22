"""WO7.0.0-004 — correlation_chains UNIQUE(org_id, artifact_id) prevents
cross-tenant chain score clobbering.

The bare UNIQUE on artifact_id collapsed two orgs ingesting the same
artifact into one cached row. The SQLite UPDATE path overwrote chain_score
WITHOUT updating org_id — cross-tenant leak + lost scores. This gate proves
two orgs ingesting the same artifact get independent cached chain rows and
neither UPDATE overwrites the other's org_id or chain_score.
"""

from __future__ import annotations

import pytest

from picosentry._core.models import Confidence, Severity
from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.services.correlation import CorrelatedEvent, CorrelationEngine


@pytest.fixture
def db_manager(tmp_path):
    db_path = tmp_path / "correlation_chain_tenant.db"
    manager = DatabaseManager(db_path=db_path, backend="sqlite")
    yield manager
    manager.close()


@pytest.fixture
def engine(db_manager, monkeypatch):
    from picosentry.serve.database import manager as db_module

    monkeypatch.setattr(db_module, "db", db_manager)
    e = CorrelationEngine()
    e.PERSIST_ENABLED = True
    yield e
    e.clear()


def _make_event(artifact_id, org_id, rule_id="L2-TYPO-001", severity=Severity.HIGH):
    return CorrelatedEvent(
        artifact_id=artifact_id,
        layer="scan",
        rule_id=rule_id,
        severity=severity,
        confidence=Confidence.HIGH,
        target="test-project",
        title="Typosquat detected",
        detail="Looks like legit-pkg",
        timestamp="2026-06-03T12:00:00+00:00",
        run_id="run-001",
        org_id=org_id,
    )


def _get_chain_row(org_id, artifact_id):
    from picosentry.serve.database import manager as db_module

    if org_id is None:
        return db_module.db.execute_one(
            "SELECT artifact_id, chain_score, org_id, event_count FROM correlation_chains "
            "WHERE org_id IS NULL AND artifact_id = ?",
            (artifact_id,),
        )
    return db_module.db.execute_one(
        "SELECT artifact_id, chain_score, org_id, event_count FROM correlation_chains "
        "WHERE org_id = ? AND artifact_id = ?",
        (org_id, artifact_id),
    )


class TestCorrelationChainsCrossTenantIsolation:
    """WO7.0.0-004: two orgs ingesting the same artifact get independent rows."""

    def test_two_orgs_same_artifact_get_independent_rows(self, engine):
        org_a, org_b = "1", "2"
        artifact = "shared-pkg@1.0.0"

        engine.ingest(_make_event(artifact, org_a, severity=Severity.HIGH))
        engine.ingest(_make_event(artifact, org_b, severity=Severity.LOW))

        engine.kill_chain(artifact, org_id=org_a)
        engine.kill_chain(artifact, org_id=org_b)

        engine.persist_chains_cache()

        from picosentry.serve.database import manager as db_module

        count = db_module.db.execute_one(
            "SELECT COUNT(*) AS c FROM correlation_chains WHERE artifact_id = ?",
            (artifact,),
        )
        assert count["c"] == 2, f"expected 2 rows for same artifact across orgs, got {count['c']}"

        row_a = _get_chain_row(org_a, artifact)
        row_b = _get_chain_row(org_b, artifact)
        assert row_a is not None, "org A's chain row missing"
        assert row_b is not None, "org B's chain row missing"
        assert str(row_a["org_id"]) == org_a
        assert str(row_b["org_id"]) == org_b

    def test_update_does_not_clobber_other_org_score(self, engine):
        org_a, org_b = "1", "2"
        artifact = "shared-pkg@1.0.0"

        engine.ingest(_make_event(artifact, org_a, severity=Severity.HIGH))
        engine.kill_chain(artifact, org_id=org_a)
        engine.persist_chains_cache()

        row_a_before = _get_chain_row(org_a, artifact)
        score_a_before = row_a_before["chain_score"]

        engine.ingest(_make_event(artifact, org_b, severity=Severity.LOW))
        engine.kill_chain(artifact, org_id=org_b)
        engine.persist_chains_cache()

        row_a_after = _get_chain_row(org_a, artifact)
        assert row_a_after is not None, "org A's row was deleted by org B's persist"
        assert str(row_a_after["org_id"]) == org_a, "org A's org_id was clobbered by org B"
        assert row_a_after["chain_score"] == score_a_before, "org A's score was clobbered by org B"

        row_b = _get_chain_row(org_b, artifact)
        assert row_b is not None, "org B's row missing"
        assert str(row_b["org_id"]) == org_b

    def test_re_persist_updates_same_org_row_not_insert_duplicate(self, engine):
        org_a = "1"
        artifact = "pkg@1.0.0"

        engine.ingest(_make_event(artifact, org_a))
        engine.kill_chain(artifact, org_id=org_a)
        engine.persist_chains_cache()
        engine.persist_chains_cache()

        from picosentry.serve.database import manager as db_module

        count = db_module.db.execute_one(
            "SELECT COUNT(*) AS c FROM correlation_chains WHERE org_id = ? AND artifact_id = ?",
            (org_a, artifact),
        )
        assert count["c"] == 1, f"re-persist should update not insert, got {count['c']} rows"

    def test_null_org_chain_isolated_from_org_chains(self, engine):
        artifact = "shared-pkg@1.0.0"
        org_a = "1"

        engine.ingest(_make_event(artifact, None))
        engine.ingest(_make_event(artifact, org_a))
        engine.kill_chain(artifact, org_id=None)
        engine.kill_chain(artifact, org_id=org_a)
        engine.persist_chains_cache()

        null_row = _get_chain_row(None, artifact)
        org_row = _get_chain_row(org_a, artifact)
        assert null_row is not None, "null-org row missing"
        assert org_row is not None, "org A row missing"
        assert null_row["org_id"] is None
        assert str(org_row["org_id"]) == org_a
