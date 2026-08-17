"""WO4.0.0-005: correlation/report/alert surfaces are tenant-scoped.

Org B must never see org A's chains, reports, intelligence, or suppress org
A's alerts; the primary producer (orchestrator intel ingestion) stamps org on
every event, and escalation is scoped to the running tenant.
"""

from __future__ import annotations

import pytest

from picosentry._core.models import Confidence, Severity
from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.services.correlation import CorrelatedEvent, CorrelationEngine
from picosentry.serve.services.correlation.helpers import build_event_from_intel


def _event(artifact: str, org: str | None, rule: str = "L2-TYPO-001", sev: Severity = Severity.CRITICAL):
    return CorrelatedEvent(
        artifact_id=artifact,
        layer="scan",
        rule_id=rule,
        severity=sev,
        confidence=Confidence.EXACT,
        target="test-project",
        title="Typosquat detected",
        detail="Looks like legit-pkg",
        timestamp="2026-06-03T12:00:00+00:00",
        org_id=org,
        run_id="run-001",
    )


class TestEngineTenancy:
    def test_org_b_chains_exclude_org_a_artifacts(self):
        engine = CorrelationEngine()
        engine.ingest(_event("orga-pkg@1.0.0", "1"))
        engine.ingest(_event("orgb-pkg@1.0.0", "2"))

        # int org ids (as the routers pass them) coerce to the engine's str space
        assert engine.kill_chain("orga-pkg@1.0.0", org_id=2) is None
        assert engine.kill_chain("orga-pkg@1.0.0", org_id=1) is not None

        critical_b = {c.artifact_id for c in engine.critical_chains(threshold=0.5, org_id=2)}
        assert critical_b == {"orgb-pkg@1.0.0"}
        assert set(engine.all_artifact_ids(org_id=2)) == {"orgb-pkg@1.0.0"}

    def test_build_event_from_intel_stamps_org(self):
        intel = {"type": "typosquat", "severity": "critical", "data": {"package": "pck@1"}, "confidence": 0.95}

        stamped = build_event_from_intel(intel, "proj", org_id=7)
        unstamped = build_event_from_intel(intel, "proj")

        assert stamped is not None and stamped.org_id == "7"
        assert unstamped is not None and unstamped.org_id is None

    def test_on_run_completed_escalates_only_the_running_org(self):
        engine = CorrelationEngine()
        escalated: list[str] = []
        engine.on_chain_escalated(lambda chain: escalated.append(chain.artifact_id))
        engine.ingest(_event("orga-crit@1", "1"))
        engine.ingest(_event("orgb-crit@1", "2"))

        engine.on_run_completed("proj", run_id="r", org_id="1")

        assert escalated == ["orga-crit@1"]

    def test_cooldown_does_not_leak_between_orgs(self):
        from picosentry.serve.services.alert_hub import AlertHub

        hub = AlertHub()
        hub.send("shared-proj", "project_failed", "high", "msg", channels=[], org_id=1)
        hub.send("shared-proj", "project_failed", "high", "msg", channels=[], org_id=1)  # suppressed
        hub.send("shared-proj", "project_failed", "high", "msg", channels=[], org_id=2)

        # org 1's second alert was cooldown-suppressed (no new timestamp);
        # org 2's alert went through despite the same project+type.
        assert len(hub.recent_alerts["1:shared-proj:project_failed"]) == 1
        assert len(hub.recent_alerts["2:shared-proj:project_failed"]) == 1


class TestPersistenceTenancy:
    @pytest.fixture
    def db_manager(self, tmp_path, monkeypatch):
        from picosentry.serve.database import manager as db_module

        mgr = DatabaseManager(db_path=tmp_path / "corr.db", backend="sqlite")
        monkeypatch.setattr(db_module, "db", mgr)
        yield mgr
        mgr.close()

    def test_org_survives_the_roundtrip_and_dedup_is_org_scoped(self, db_manager):
        engine = CorrelationEngine()
        engine.PERSIST_ENABLED = True
        engine.ingest(_event("shared@1.0.0", "1"))
        engine.ingest(_event("shared@1.0.0", "2"))  # same artifact+rule+ts, other org
        engine.ingest(_event("shared@1.0.0", "2"))  # true duplicate within org 2
        engine.persist_events()
        engine.persist_chains_cache()

        rows = db_manager.execute(
            "SELECT org_id, COUNT(*) AS c FROM correlation_events GROUP BY org_id ORDER BY org_id"
        )
        assert [(r["org_id"], r["c"]) for r in rows] == [("1", 1), ("2", 1)]

        reloaded = CorrelationEngine()
        reloaded.PERSIST_ENABLED = True
        assert reloaded.load_events() == 2
        assert reloaded.kill_chain("shared@1.0.0", org_id="1") is not None
        assert reloaded.kill_chain("shared@1.0.0", org_id="2") is not None
        assert reloaded.kill_chain("shared@1.0.0", org_id="3") is None


class TestReportsTenancy:
    def test_project_report_never_leaks_other_orgs(self):
        from picosentry.serve.database.manager import db
        from picosentry.serve.services.orchestrator import EnhancedOrchestrator

        orch = EnhancedOrchestrator()
        db.execute("DELETE FROM intelligence WHERE source_project LIKE 'tenancy-%'")
        db.execute(
            """
            INSERT INTO intelligence (source_project, intel_type, severity, data, related_projects, org_id)
            VALUES ('tenancy-src-a', 'typosquat', 'critical', '{}', 'tenancy-proj', 1),
                   ('tenancy-src-b', 'typosquat', 'critical', '{}', 'tenancy-proj', 2)
        """
        )
        db.execute("DELETE FROM org_projects WHERE project_id = 'tenancy-proj'")
        db.execute("DELETE FROM projects WHERE id = 'tenancy-proj'")
        db.execute("INSERT INTO projects (id, name) VALUES ('tenancy-proj', 'Tenancy Probe')")
        db.execute("INSERT INTO org_projects (org_id, project_id) VALUES (1, 'tenancy-proj')")

        report_a = orch.generate_project_report("tenancy-proj", org_id=1)
        assert report_a is not None
        assert [c["source"] for c in report_a["correlations"]] == ["tenancy-src-a"]

        # org 2 does not own the project -> ownership 404 path
        assert orch.generate_project_report("tenancy-proj", org_id=2) is None

        # unscoped report still sees everything (admin/system view)
        report_all = orch.generate_project_report("tenancy-proj")
        assert len(report_all["correlations"]) == 2

        db.execute("DELETE FROM intelligence WHERE source_project LIKE 'tenancy-%'")
        db.execute("DELETE FROM org_projects WHERE project_id = 'tenancy-proj'")
        db.execute("DELETE FROM projects WHERE id = 'tenancy-proj'")
