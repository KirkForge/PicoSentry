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


def _drain_sched_queue() -> None:
    """Cancel any pending entries the scheduler thread hasn't fired yet."""
    for event in list(scheduler.scheduler.queue):
        scheduler.scheduler.cancel(event)


class TestHealthCheckJob:
    """WO-012: the health_check command must actually run health checks."""

    def test_health_check_job_completes_and_populates_table(self):
        from picosentry.serve.database.manager import db

        before = db.execute_one("SELECT COUNT(*) AS c FROM health_checks")["c"]
        job_id = _add_job("health_check", {})
        try:
            scheduler._execute_job(job_id)
            assert scheduler.jobs[job_id].last_status == "completed"
            after = db.execute_one("SELECT COUNT(*) AS c FROM health_checks")["c"]
            assert after > before, "health_check job did not persist probe rows"
        finally:
            scheduler.remove_job(job_id)

    def test_health_check_runs_off_scheduler_thread(self, monkeypatch):
        """Health probes block on SMTP for up to 5s — they must run on their
        own thread (like batch) and skip while still running."""
        from picosentry.serve.services import orchestrator as orch_mod

        started = threading.Event()
        release = threading.Event()
        calls: list[int] = []

        def _slow():
            calls.append(1)
            started.set()
            assert release.wait(5)
            return []

        monkeypatch.setattr(orch_mod.orchestrator, "get_health_checks", _slow)
        job_id = _add_job("health_check", {})
        try:
            scheduler._dispatch_job(job_id)  # daemon thread, not this one
            assert started.wait(5)
            scheduler._dispatch_job(job_id)  # still running -> skip
            assert calls == [1]
        finally:
            release.set()
            scheduler.remove_job(job_id)


class TestRejectedJobsReschedule:
    """WO-012: a rejected job must be rescheduled, not silently die."""

    def test_bad_category_job_reschedules_after_rejection(self):
        job_id = scheduler.add_job(
            name=f"rejected_resched_{time.time_ns()}",
            cron="0 3 * * *",
            command="batch",
            params={"category": "evil; script"},
            enabled=True,
        )
        _drain_sched_queue()
        scheduler.running = True
        try:
            scheduler._execute_job(job_id)
            job = scheduler.jobs[job_id]
            assert job.last_status == "rejected"
            assert job.next_run is not None, "rejected job was not rescheduled"
        finally:
            scheduler.running = False
            _drain_sched_queue()
            scheduler.remove_job(job_id)

    def test_unknown_command_job_rejected_and_reschedules(self):
        """A job row with a command outside the allowlist (loaded from the DB,
        not creatable via add_job) is rejected but keeps its schedule."""
        from picosentry.serve.database.manager import db

        job_id = db.execute_insert(
            """
            INSERT INTO scheduled_jobs (name, cron_expression, command, params, enabled, org_id)
            VALUES (?, '* * * * *', 'bogus_command', '{}', 1, NULL)
        """,
            (f"bogus_{time.time_ns()}",),
        )
        scheduler._load_jobs()
        _drain_sched_queue()
        scheduler.running = True
        try:
            scheduler._execute_job(job_id)
            job = scheduler.jobs[job_id]
            assert job.last_status == "rejected"
            assert job.next_run is not None
        finally:
            scheduler.running = False
            _drain_sched_queue()
            scheduler.remove_job(job_id)


class TestReportJobDelivery:
    """WO-012: scheduled reports must be stored/delivered, not discarded."""

    def test_report_job_stores_row_via_alert_hub(self, monkeypatch):
        from picosentry.serve.database.manager import db
        from picosentry.serve.services import orchestrator as orch_mod

        marker = f"REPORT-{time.time_ns()}"
        monkeypatch.setattr(orch_mod.orchestrator, "generate_summary_report", lambda org_id=None: marker)

        job_id = _add_job("report", {})
        try:
            scheduler._execute_job(job_id)
            assert scheduler.jobs[job_id].last_status == "completed"
            row = db.execute_one(
                "SELECT message FROM alerts WHERE alert_type = ? ORDER BY id DESC LIMIT 1",
                ("scheduled_report",),
            )
            assert row is not None, "scheduled report produced no stored output"
            assert marker in row["message"]
        finally:
            scheduler.remove_job(job_id)
            db.execute("DELETE FROM alerts WHERE alert_type = 'scheduled_report'")


class TestUpdateAndTrigger:
    """WO-012: update_job recovers a misconfigured job; trigger_job runs now."""

    def test_update_job_changes_cron_and_params(self):
        job_id = _add_job("batch", {"category": "monitoring"})
        try:
            assert scheduler.update_job(job_id, cron="0 1 * * *", params={"category": "audit"})
            job = scheduler.jobs[job_id]
            assert job.cron_expression == "0 1 * * *"
            assert job.params == {"category": "audit"}
        finally:
            scheduler.remove_job(job_id)

    def test_update_job_rejects_invalid_cron(self):
        import pytest

        job_id = _add_job("cleanup", {})
        try:
            with pytest.raises(ValueError, match="Invalid cron"):
                scheduler.update_job(job_id, cron="not-a-cron")
        finally:
            scheduler.remove_job(job_id)

    def test_update_job_unknown_id_is_false(self):
        assert not scheduler.update_job(999999, cron="0 1 * * *")

    def test_trigger_job_dispatches_now(self, monkeypatch):
        calls: list[int] = []
        monkeypatch.setattr(scheduler, "_dispatch_job", lambda jid: calls.append(jid))
        job_id = _add_job("cleanup", {})
        scheduler.enable_job(job_id)
        try:
            assert scheduler.trigger_job(job_id)
            assert calls == [job_id]
        finally:
            scheduler.remove_job(job_id)

    def test_trigger_job_disabled_is_rejected(self, monkeypatch):
        calls: list[int] = []
        monkeypatch.setattr(scheduler, "_dispatch_job", lambda jid: calls.append(jid))
        job_id = _add_job("cleanup", {})  # _add_job creates disabled jobs
        try:
            assert not scheduler.trigger_job(job_id)
            assert calls == []
        finally:
            scheduler.remove_job(job_id)
