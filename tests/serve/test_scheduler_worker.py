"""Scheduler hardening: module-relative batch script, off-thread slow jobs,
org-stamped scheduler runs (tenancy leak at its biggest source)."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from picosentry.serve.database.manager import db
from picosentry.serve.services import scheduler as sched_mod
from picosentry.serve.services.scheduler import scheduler


def _add_job(command: str, params: dict, org_id: int | None = None) -> int:
    return scheduler.add_job(
        name=f"worker_{command}_{time.time_ns()}",
        cron="* * * * *",
        command=command,
        params=params,
        enabled=False,
        org_id=org_id,
    )


class TestBatchScriptResolution:
    def test_repo_root_is_module_relative(self):
        assert Path(sched_mod.__file__).resolve().parents[3] == sched_mod._REPO_ROOT

    def test_missing_script_fails_with_clear_status(self, caplog):
        job_id = _add_job("batch", {"category": "monitoring"})
        try:
            with caplog.at_level("ERROR", logger="picoshogun.Scheduler"):
                scheduler._execute_job(job_id)
            assert scheduler.jobs[job_id].last_status == "failed"
            assert any("Batch script not found" in r.message for r in caplog.records)
        finally:
            scheduler.remove_job(job_id)

    def test_present_script_runs_from_any_cwd(self, tmp_path, monkeypatch):
        (tmp_path / "scripts").mkdir()
        (tmp_path / "scripts" / "run_category.sh").write_text("#!/bin/bash\necho ok\n")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.setattr(sched_mod, "_REPO_ROOT", tmp_path)
        monkeypatch.chdir(elsewhere)

        job_id = _add_job("batch", {"category": "monitoring"})
        try:
            scheduler._execute_job(job_id)
            assert scheduler.jobs[job_id].last_status == "completed"
        finally:
            scheduler.remove_job(job_id)


class TestSlowJobOffSchedulerThread:
    def test_fast_job_runs_inline(self, monkeypatch):
        calls: list[int] = []
        monkeypatch.setattr(scheduler, "_execute_job", lambda jid: calls.append(jid))
        job_id = _add_job("cleanup", {})
        try:
            scheduler._dispatch_job(job_id)
            assert calls == [job_id]
        finally:
            scheduler.remove_job(job_id)

    def test_batch_job_runs_off_thread_and_skips_while_running(self, monkeypatch):
        started = threading.Event()
        release = threading.Event()
        calls: list[int] = []

        def _slow(jid):
            calls.append(jid)
            started.set()
            assert release.wait(5)

        monkeypatch.setattr(scheduler, "_execute_job", _slow)
        job_id = _add_job("batch", {"category": "monitoring"})
        try:
            scheduler._dispatch_job(job_id)  # runs on a daemon thread
            assert started.wait(5)
            scheduler._dispatch_job(job_id)  # still running -> skip, don't stack
            assert calls == [job_id]
        finally:
            release.set()
            scheduler.remove_job(job_id)
        deadline = time.monotonic() + 5
        while job_id in scheduler._slow_running and time.monotonic() < deadline:
            time.sleep(0.01)
        assert job_id not in scheduler._slow_running


class TestOrgStampedRuns:
    def test_job_org_takes_precedence(self):
        job_id = _add_job("run", {"project_id": "whatever"}, org_id=7)
        try:
            assert scheduler._org_for_run(job_id, "whatever") == 7
        finally:
            scheduler.remove_job(job_id)

    def test_unowned_job_falls_back_to_project_mapping(self):
        ns = time.time_ns()
        project_id = f"proj-{ns}"
        org_id = db.execute_insert("INSERT INTO orgs (name, slug) VALUES (?, ?)", (f"org-{ns}", f"slug-{ns}"))
        db.execute_insert("INSERT INTO org_projects (org_id, project_id) VALUES (?, ?)", (org_id, project_id))
        job_id = _add_job("run", {"project_id": project_id})
        try:
            assert scheduler._org_for_run(job_id, project_id) == org_id
        finally:
            scheduler.remove_job(job_id)
            db.execute_insert("DELETE FROM org_projects WHERE org_id = ?", (org_id,))
            db.execute_insert("DELETE FROM orgs WHERE id = ?", (org_id,))

    def test_unknown_project_has_no_org(self):
        assert scheduler._org_for_run(999999, "no-such-project") is None

    def test_execute_run_passes_org_to_run_project(self, monkeypatch):
        from picosentry.serve.services import orchestrator as orch_mod

        seen: dict = {}

        def _record_run(pid, timeout, org_id=None):
            seen.update(pid=pid, timeout=timeout, org_id=org_id)
            return {"success": True}

        monkeypatch.setattr(orch_mod.orchestrator, "run_project", _record_run)
        job_id = _add_job("run", {"project_id": "proj-org", "timeout": 42}, org_id=7)
        try:
            scheduler._execute_job(job_id)
            assert seen == {"pid": "proj-org", "timeout": 42, "org_id": 7}
            assert scheduler.jobs[job_id].last_status == "completed"
        finally:
            scheduler.remove_job(job_id)
