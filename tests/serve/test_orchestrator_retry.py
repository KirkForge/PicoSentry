"""retry_failed actually re-runs the project (was: log-only no-op)."""

from __future__ import annotations

import subprocess as subprocess_mod
from typing import ClassVar
from unittest.mock import MagicMock

import pytest

from picosentry.serve.services import orchestrator as orch_mod
from picosentry.serve.services.orchestrator import EnhancedOrchestrator, ProjectMeta


class _FakeTimer:
    created: ClassVar[list[_FakeTimer]] = []

    def __init__(self, interval, function, args=None, kwargs=None):
        self.interval = interval
        self.function = function
        self.args = args or ()
        self.kwargs = kwargs or {}
        self.daemon = False
        type(self).created.append(self)

    def start(self):
        pass

    def cancel(self):
        pass


@pytest.fixture(autouse=True)
def _fake_timers(monkeypatch):
    _FakeTimer.created = []
    monkeypatch.setattr("threading.Timer", _FakeTimer)


@pytest.fixture
def orch(tmp_path, monkeypatch):
    monkeypatch.setenv("PICOSHOGUN_DATABASE_PATH", str(tmp_path / "orch.db"))
    instance = EnhancedOrchestrator()
    for pid in ("retry-project", "retry-project-cap"):
        instance.registry[pid] = ProjectMeta(
            id=pid,
            name="Retry",
            category="scan",
            priority=1,
            dependencies=[],
            cron_schedule="",
            estimated_duration=1,
            status="active",
            version="1.0.0",
        )
    instance.alerts.send = MagicMock()
    monkeypatch.setattr(orch_mod.plugin_manager, "dispatch", MagicMock())
    monkeypatch.setattr(orch_mod.event_bus, "publish", MagicMock())
    return instance


def _failing_subprocess(monkeypatch) -> dict:
    calls = {"n": 0}

    def _run(*args, **kwargs):
        calls["n"] += 1
        return subprocess_mod.CompletedProcess(args=args, returncode=1, stdout="", stderr="boom")

    monkeypatch.setattr(orch_mod.subprocess, "run", _run)
    return calls


def test_failed_run_schedules_and_runs_retry(orch, monkeypatch):
    from picosentry.serve.config.settings import settings

    monkeypatch.setattr(settings.orchestrator, "retry_failed", True)
    monkeypatch.setattr(settings.orchestrator, "retry_max", 1)
    monkeypatch.setattr(settings.orchestrator, "retry_delay", 60)
    calls = _failing_subprocess(monkeypatch)

    result = orch.run_project("retry-project")
    assert result["success"] is False
    assert len(_FakeTimer.created) == 1
    timer = _FakeTimer.created[0]
    assert timer.interval == 60
    assert timer.daemon is True  # an in-flight retry must not block exit

    timer.function(*timer.args, **timer.kwargs)  # fire the retry synchronously
    assert calls["n"] == 2
    assert len(_FakeTimer.created) == 1  # retry_max=1: the retry itself is not re-retried


def test_retry_respects_retry_max(orch, monkeypatch):
    from picosentry.serve.config.settings import settings

    monkeypatch.setattr(settings.orchestrator, "retry_failed", True)
    monkeypatch.setattr(settings.orchestrator, "retry_max", 2)
    _failing_subprocess(monkeypatch)

    orch.run_project("retry-project-cap")
    assert len(_FakeTimer.created) == 1
    _FakeTimer.created[0].function(*_FakeTimer.created[0].args)
    assert len(_FakeTimer.created) == 2  # second failure still under the cap
    _FakeTimer.created[1].function(*_FakeTimer.created[1].args)
    assert len(_FakeTimer.created) == 2  # cap reached: no third retry


def test_retry_disabled_schedules_nothing(orch, monkeypatch):
    from picosentry.serve.config.settings import settings

    monkeypatch.setattr(settings.orchestrator, "retry_failed", False)
    _failing_subprocess(monkeypatch)

    result = orch.run_project("retry-project")
    assert result["success"] is False
    assert _FakeTimer.created == []
