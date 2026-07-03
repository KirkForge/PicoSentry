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
        assert "db connection lost" in db_check["message"]

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
