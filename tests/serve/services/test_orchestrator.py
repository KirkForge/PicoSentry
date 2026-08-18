"""EnhancedOrchestrator exception-narrowing + basic contract tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from picosentry.serve.services.orchestrator import EnhancedOrchestrator, ProjectMeta


@pytest.fixture
def orchestrator(tmp_path, monkeypatch):
    """A minimal EnhancedOrchestrator with one registered project."""
    monkeypatch.setenv("PICOSHOGUN_DATABASE_PATH", str(tmp_path / "orch.db"))
    orch = EnhancedOrchestrator()
    orch.registry["test-project"] = ProjectMeta(
        id="test-project",
        name="Test Project",
        category="scan",
        priority=1,
        dependencies=[],
        cron_schedule="",
        estimated_duration=1,
        status="active",
        version="1.0.0",
    )
    return orch


class TestExecuteProjectExceptionHandling:
    def test_runtime_error_is_sanitized(self, orchestrator, monkeypatch, caplog):
        from picosentry.serve.services import orchestrator as orch_mod

        orchestrator.alerts.send = MagicMock()
        orch_mod.plugin_manager.dispatch = MagicMock()
        orch_mod.event_bus.publish = MagicMock()

        def _boom(*args, **kwargs):
            raise RuntimeError("internal secret details")

        monkeypatch.setattr(orch_mod.subprocess, "run", _boom)

        with caplog.at_level("ERROR", logger="picoshogun.Orchestrator"):
            result = orchestrator.run_project("test-project")

        assert result["error"] == "project execution failed"
        assert "internal secret details" not in result["error"]
        assert "RuntimeError" not in result["error"]

        orchestrator.alerts.send.assert_called_once()
        alert_message = orchestrator.alerts.send.call_args[1].get("message", "")
        assert "internal secret details" not in alert_message

        failed_calls = [c for c in orch_mod.event_bus.publish.call_args_list if c.args[0] == "project.run.failed"]
        assert len(failed_calls) == 1
        payload = failed_calls[0].args[1]
        assert payload.get("error") == "project execution failed"
        assert "internal secret details" not in payload.get("error", "")

        assert any("Project execution failed" in r.message for r in caplog.records)

    def test_unexpected_programmer_error_propagates(self, orchestrator, monkeypatch):
        from picosentry.serve.services import orchestrator as orch_mod

        def _buggy(*args, **kwargs):
            raise NameError("programmer bug")

        monkeypatch.setattr(orch_mod.subprocess, "run", _buggy)

        with pytest.raises(NameError, match="programmer bug"):
            orchestrator.run_project("test-project")


class TestHealthCheckHardening:
    """Health probes must report degraded status for expected failures but surface programmer errors."""

    def test_database_probe_failure_reported_critical(self, orchestrator, monkeypatch):
        def _boom(*args, **kwargs):
            raise RuntimeError("db connection lost")

        monkeypatch.setattr(orchestrator, "registry", {"test-project": MagicMock()})
        monkeypatch.setattr(orchestrator.alerts, "send", MagicMock())
        monkeypatch.setattr("picosentry.serve.services.orchestrator.db.execute", _boom)

        checks = orchestrator.get_health_checks()
        db_check = next(c for c in checks if c["component"] == "database")
        assert db_check["status"] == "critical"
        assert db_check["message"] == "Database unreachable"

    def test_disk_space_probe_failure_reported_unknown(self, orchestrator, monkeypatch):
        import os

        monkeypatch.setattr(orchestrator, "registry", {"test-project": MagicMock()})
        monkeypatch.setattr(orchestrator.alerts, "send", MagicMock())
        monkeypatch.setattr(os, "statvfs", lambda *args, **kwargs: (_ for _ in ()).throw(PermissionError("denied")))

        checks = orchestrator.get_health_checks()
        disk_check = next(c for c in checks if c["component"] == "disk_space")
        assert disk_check["status"] == "unknown"

    def test_smtp_probe_failure_reported_critical(self, orchestrator, monkeypatch):
        import smtplib

        monkeypatch.setattr(orchestrator, "registry", {"test-project": MagicMock()})
        monkeypatch.setattr(orchestrator.alerts, "send", MagicMock())
        monkeypatch.setattr(
            "picosentry.serve.services.orchestrator.settings.alerts.email_smtp_host", "smtp.example.com"
        )
        monkeypatch.setattr("picosentry.serve.services.orchestrator.settings.alerts.email_smtp_port", 587)
        monkeypatch.setattr(
            smtplib,
            "SMTP",
            lambda *args, **kwargs: (_ for _ in ()).throw(smtplib.SMTPConnectError(421, "cannot connect")),
        )

        checks = orchestrator.get_health_checks()
        smtp_check = next(c for c in checks if c["component"] == "smtp")
        assert smtp_check["status"] == "critical"

    def test_unexpected_health_probe_error_propagates(self, orchestrator, monkeypatch):
        def _buggy(*args, **kwargs):
            raise NameError("programmer bug")

        monkeypatch.setattr(orchestrator, "registry", {"test-project": MagicMock()})
        monkeypatch.setattr(orchestrator.alerts, "send", MagicMock())
        monkeypatch.setattr("picosentry.serve.services.orchestrator.db.execute", _buggy)

        with pytest.raises(NameError, match="programmer bug"):
            orchestrator.get_health_checks()


class TestOrchestratorHelpers:
    """Direct tests for helper modules extracted from EnhancedOrchestrator."""

    def test_perform_health_checks_imports_and_runs(self, orchestrator, monkeypatch):
        from picosentry.serve.services._orchestrator_health import perform_health_checks

        monkeypatch.setattr(
            "picosentry.serve.services._orchestrator_health.smtplib.SMTP",
            lambda *args, **kwargs: MagicMock(),
        )
        checks = perform_health_checks(orchestrator.registry)
        components = {c["component"] for c in checks}
        assert "database" in components
        assert "disk_space" in components
        assert "projects" in components

    def test_update_project_stats_writes_run_count(self, orchestrator, monkeypatch):
        from picosentry.serve.services._orchestrator_stats import update_project_stats

        monkeypatch.setattr(
            "picosentry.serve.services._orchestrator_stats.db.execute_one",
            lambda _q, _p: {"total": 5, "success": 4, "avg_dur": 1.2},
        )
        calls = []
        monkeypatch.setattr(
            "picosentry.serve.services._orchestrator_stats.db.execute_insert",
            lambda _q, p: calls.append(p),
        )

        update_project_stats("test-project")
        assert len(calls) == 1
        assert calls[0][4] == "test-project"


class TestRunOutputBounding:
    """WO-021: project_runs.output is bounded — unbounded stdout per run
    would grow the DB without limit on chatty projects."""

    def test_short_output_unchanged(self):
        from picosentry.serve.services.orchestrator import _RUN_OUTPUT_LIMIT, _bounded

        assert _bounded("short") == "short"
        assert _bounded("x" * _RUN_OUTPUT_LIMIT) == "x" * _RUN_OUTPUT_LIMIT  # at the limit: intact

    def test_long_output_truncated_with_flag(self):
        from picosentry.serve.services.orchestrator import _RUN_OUTPUT_LIMIT, _bounded

        bounded = _bounded("x" * (_RUN_OUTPUT_LIMIT + 5000))
        assert bounded.startswith("x" * 100)
        assert bounded.endswith("\n...[truncated]")
        assert len(bounded) <= _RUN_OUTPUT_LIMIT + len("\n...[truncated]")


class TestOrgScopedThreatScore:
    """WO5.0.0-022: /status threat_score must not blend other orgs' intel."""

    def test_org_a_status_unaffected_by_org_b_ingest(self):
        from picosentry.serve.database.manager import db
        from picosentry.serve.services.orchestrator import orchestrator

        org_a, org_b = 555001, 555002
        before = orchestrator.get_status(org_id=org_a)["threat_score"]
        try:
            orchestrator.intel.ingest(
                f"orgb-proj-{org_b}",
                {
                    "type": "anomaly",
                    "severity": "critical",
                    "data": {"match_count": 5},
                    "related": [],
                    "confidence": 0.9,
                },
                org_id=org_b,
            )
            after = orchestrator.get_status(org_id=org_a)["threat_score"]
            assert after == before, "org B ingest leaked into org A's threat score"

            assert orchestrator.get_status(org_id=org_b)["threat_score"] > 0
            assert orchestrator.get_status()["threat_score"] > 0  # global view unchanged
        finally:
            db.execute(f"DELETE FROM intelligence WHERE org_id IN ({org_a}, {org_b})")
            orchestrator.intel.threat_scores.pop(f"orgb-proj-{org_b}", None)
