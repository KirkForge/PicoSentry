"""Focused unit tests for the PicoShogun job scheduler.

These tests cover security-relevant validation that is hard to exercise
through the HTTP API alone (e.g. batch category allowlist enforcement).
"""

import time

import pytest

from picosentry.serve.services.scheduler import JobScheduler, scheduler


class TestCategoryAllowlist:
    """Batch job categories must match a known-good allowlist."""

    def test_allowed_categories_accepted(self):
        for category in JobScheduler.ALLOWED_CATEGORIES:
            assert scheduler._validate_category(category), f"{category!r} should be allowed"

    def test_unknown_category_rejected(self):
        assert not scheduler._validate_category("monitoring; rm -rf /")
        assert not scheduler._validate_category("../../etc/passwd")
        assert not scheduler._validate_category("audit\nmalicious")

    def test_default_category_is_allowed(self):
        # The default category used when none is supplied must be in the allowlist.
        assert "monitoring" in JobScheduler.ALLOWED_CATEGORIES

    def test_execute_job_rejects_unknown_category(self):
        job_id = scheduler.add_job(
            name=f"bad_category_job_{time.time_ns()}",
            cron="* * * * *",
            command="batch",
            params={"category": "evil; script"},
            enabled=False,
        )
        scheduler._execute_job(job_id)

        job = scheduler.jobs[job_id]
        assert job.last_status == "rejected"
        scheduler.remove_job(job_id)

    def test_execute_job_attempts_allowed_category(self):
        # The category is allowed, but scripts/run_category.sh does not exist in
        # this repo, so execution itself fails rather than being rejected.
        job_id = scheduler.add_job(
            name=f"allowed_category_job_{time.time_ns()}",
            cron="* * * * *",
            command="batch",
            params={"category": "monitoring"},
            enabled=False,
        )
        scheduler._execute_job(job_id)

        job = scheduler.jobs[job_id]
        assert job.last_status == "failed"
        scheduler.remove_job(job_id)


class TestSchedulerIdempotentAdd:
    """Re-seeding a job name that already exists must not raise (restart crash-loop)."""

    def test_add_job_twice_same_name_returns_existing_id(self):
        name = f"idempotent_job_{time.time_ns()}"
        job_id = scheduler.add_job(name=name, cron="0 */6 * * *", command="cleanup", params={}, enabled=False)
        second_id = scheduler.add_job(name=name, cron="0 */6 * * *", command="cleanup", params={}, enabled=False)

        assert second_id == job_id
        assert job_id in scheduler.jobs
        scheduler.remove_job(job_id)


class TestSchedulerHardening:
    """Scheduler must log parse failures instead of silently returning None."""

    def test_invalid_cron_expression_logs_and_returns_none(self, caplog):
        import logging

        with caplog.at_level(logging.WARNING, logger="picoshogun.scheduler"):
            result = scheduler._get_next_run("not-a-cron")

        assert result is None
        assert any("Invalid cron expression" in r.message for r in caplog.records)

    def test_unexpected_cron_error_propagates(self, monkeypatch):
        from picosentry.serve.services import scheduler as sched_mod

        def _buggy(*args, **kwargs):
            raise AttributeError("programmer bug")

        monkeypatch.setattr(sched_mod, "HAS_CRONITER", True)
        monkeypatch.setattr(sched_mod.croniter, "__init__", lambda *args, **kwargs: None)
        monkeypatch.setattr(sched_mod.croniter, "get_next", _buggy)

        with pytest.raises(AttributeError, match="programmer bug"):
            scheduler._get_next_run("* * * * *")


class TestSchedulerExecuteExceptionNarrowing:
    """Scheduled job execution must log expected failures and propagate bugs."""

    @staticmethod
    def _with_script_present(tmp_path, monkeypatch):
        """Point the batch runner at a repo root whose script exists, so the
        subprocess path (and its exception handling) is actually reached."""
        from picosentry.serve.services import scheduler as sched_mod

        (tmp_path / "scripts").mkdir(exist_ok=True)
        (tmp_path / "scripts" / "run_category.sh").write_text("#!/bin/bash\nexit 0\n")
        monkeypatch.setattr(sched_mod, "_REPO_ROOT", tmp_path)

    def test_execute_job_expected_oserror_is_logged(self, caplog, monkeypatch, tmp_path):
        import logging

        self._with_script_present(tmp_path, monkeypatch)
        job_id = scheduler.add_job(
            name=f"expected_error_job_{time.time_ns()}",
            cron="* * * * *",
            command="batch",
            params={"category": "monitoring"},
            enabled=False,
        )

        def _boom(*args, **kwargs):
            raise PermissionError("denied")

        monkeypatch.setattr("subprocess.run", _boom)

        with caplog.at_level(logging.ERROR, logger="picoshogun.Scheduler"):
            scheduler._execute_job(job_id)

        assert scheduler.jobs[job_id].last_status == "failed"
        assert any("Job" in r.message and "failed" in r.message for r in caplog.records)
        scheduler.remove_job(job_id)

    def test_execute_job_unexpected_error_propagates(self, monkeypatch, tmp_path):
        self._with_script_present(tmp_path, monkeypatch)
        job_id = scheduler.add_job(
            name=f"unexpected_error_job_{time.time_ns()}",
            cron="* * * * *",
            command="batch",
            params={"category": "monitoring"},
            enabled=False,
        )

        def _boom(*args, **kwargs):
            raise NameError("programmer mistake")

        monkeypatch.setattr("subprocess.run", _boom)

        with pytest.raises(NameError, match="programmer mistake"):
            scheduler._execute_job(job_id)

        scheduler.remove_job(job_id)


class TestCleanupJobSeverityRetention:
    """WO5.0.0-006: the automatic periodic cleanup job must use the per-severity
    retention policy (critical 365d / high 180d), not the flat
    audit_retention_days window — the flat override is admin-endpoint-only."""

    def test_periodic_cleanup_keeps_critical_and_high_past_flat_window(self, tmp_path, monkeypatch):
        from datetime import datetime, timedelta, timezone

        from picosentry.serve.database.manager import DatabaseManager
        from picosentry.serve.services import scheduler as sched_mod
        from picosentry.serve.services.audit_cleanup import SQLITE_TS
        import picosentry.serve.services.audit_cleanup as cleanup_mod

        mgr = DatabaseManager(db_path=tmp_path / "sched-audit.db")
        monkeypatch.setattr(sched_mod, "db", mgr)
        monkeypatch.setattr(cleanup_mod, "db", mgr)

        # All three older than the flat 90d window; only low is outside its
        # per-severity policy (critical 365d, high 180d, low 30d).
        created = (datetime.now(timezone.utc) - timedelta(days=100)).strftime(SQLITE_TS)
        for severity in ("critical", "high", "low"):
            mgr.execute(
                """
                INSERT INTO audit_log (action, user_id, resource_type, resource_id, details,
                    ip_address, user_agent, prev_hash, row_hash, org_id, severity, created_at)
                VALUES ('GET', 1, 'api', '/wo5-006', '{}', NULL, NULL, '', '', NULL, ?, ?)
            """,
                (severity, created),
            )

        job_id = scheduler.add_job(
            name=f"wo5_cleanup_{time.time_ns()}",
            cron="0 */6 * * *",
            command="cleanup",
            params={},
            enabled=False,
        )
        try:
            scheduler._execute_job(job_id)

            assert scheduler.jobs[job_id].last_status == "completed"
            rows = mgr.execute(
                "SELECT severity FROM audit_log WHERE resource_id = '/wo5-006' AND action != 'audit.purge'"
            )
            assert sorted(r["severity"] for r in rows) == ["critical", "high"]
        finally:
            scheduler.remove_job(job_id)
            mgr.close()


class TestSchedulerQueueUniqueness:
    """WO5.0.0-021: boot/toggle cycles must leave exactly ONE queued entry per job.

    _schedule_job never canceled the existing entry, so boot order (start()
    then lifespan add_job) permanently doubled every system job and
    update_job/enable_job multiplied further.
    """

    @staticmethod
    def _count_entries(instance: JobScheduler, job_id: int) -> int:
        return sum(1 for e in instance.scheduler.queue if e.argument == (job_id,))

    def test_boot_update_enable_restart_never_multiply(self, tmp_path, monkeypatch):
        from picosentry.serve.database.manager import DatabaseManager
        from picosentry.serve.services import scheduler as sched_mod

        mgr = DatabaseManager(db_path=tmp_path / "sched-queue.db")
        monkeypatch.setattr(sched_mod, "db", mgr)

        s = sched_mod.JobScheduler()
        job_id = s.add_job(name="nightly_backup", cron="0 2 * * *", command="backup", params={}, enabled=True)
        assert self._count_entries(s, job_id) == 0  # not running yet: nothing queued

        # The worker loop is irrelevant here; stub it so stop() is instant.
        monkeypatch.setattr(s, "_run", lambda: None)
        s.start()
        assert self._count_entries(s, job_id) == 1

        # Lifespan boot order re-seeds the same job after start().
        assert s.add_job(name="nightly_backup", cron="0 2 * * *", command="backup", params={}, enabled=True) == job_id
        assert self._count_entries(s, job_id) == 1

        s.update_job(job_id, cron="*/30 * * * *")
        assert self._count_entries(s, job_id) == 1

        s.enable_job(job_id)
        assert self._count_entries(s, job_id) == 1

        # Process restart: a fresh scheduler loads the persisted job.
        s2 = sched_mod.JobScheduler()
        monkeypatch.setattr(s2, "_run", lambda: None)
        s2.start()
        try:
            assert self._count_entries(s2, job_id) == 1
        finally:
            s2.stop()
            mgr.close()
        s.stop()

        # Disabled jobs must not keep a pending entry that still fires.
        mgr2 = DatabaseManager(db_path=tmp_path / "sched-queue.db")
        monkeypatch.setattr(sched_mod, "db", mgr2)
        s3 = sched_mod.JobScheduler()
        monkeypatch.setattr(s3, "_run", lambda: None)
        s3.start()
        assert self._count_entries(s3, job_id) == 1
        s3.disable_job(job_id)
        assert self._count_entries(s3, job_id) == 0
        s3.stop()
        mgr2.close()


class TestSameNameJobCreation:
    """WO5.0.0-021: same org + name + config -> existing id; different config -> 409."""

    def test_different_config_conflicts(self, tmp_path, monkeypatch):
        from picosentry.serve.database.manager import DatabaseManager
        from picosentry.serve.services import scheduler as sched_mod
        from picosentry.serve.services.scheduler import SchedulerJobConflict

        mgr = DatabaseManager(db_path=tmp_path / "sched-name.db")
        monkeypatch.setattr(sched_mod, "db", mgr)
        s = sched_mod.JobScheduler()

        job_id = s.add_job(name="dup-job", cron="0 2 * * *", command="backup", params={}, enabled=False)
        with pytest.raises(SchedulerJobConflict):
            s.add_job(name="dup-job", cron="*/5 * * * *", command="backup", params={}, enabled=False)
        with pytest.raises(SchedulerJobConflict):
            s.add_job(name="dup-job", cron="0 2 * * *", command="cleanup", params={}, enabled=False)
        with pytest.raises(SchedulerJobConflict):
            s.add_job(name="dup-job", cron="0 2 * * *", command="backup", params={"k": "v"}, enabled=False)
        # Same config is still idempotent (restart re-seed path).
        assert s.add_job(name="dup-job", cron="0 2 * * *", command="backup", params={}, enabled=False) == job_id
        mgr.close()


class TestScheduledReportOrgScoping:
    """WO5.0.0-021: org X's scheduled report must contain only org X's data."""

    def test_report_job_delivers_org_scoped_report(self):
        from picosentry.serve.api.server import auth_service
        from picosentry.serve.database.manager import db
        from picosentry.serve.services.orgs import Organization
        from picosentry.serve.services.orchestrator import orchestrator

        tag = time.time_ns()
        user_id = auth_service.create_user(f"report_user_{tag}", "testpassword123")
        org_a = Organization.create(name=f"RepA {tag}", slug=f"rep-a-{tag}", owner_user_id=user_id)["org_id"]
        org_b = Organization.create(name=f"RepB {tag}", slug=f"rep-b-{tag}", owner_user_id=user_id)["org_id"]
        Organization.add_project(org_a, f"alpha-proj-{tag}")
        Organization.add_project(org_b, f"beta-proj-{tag}")
        orchestrator.intel.ingest(
            f"alpha-proj-{tag}",
            {"type": "anomaly", "severity": "high", "data": {"match_count": 3}, "related": [], "confidence": 0.9},
            org_id=org_a,
        )
        orchestrator.intel.ingest(
            f"beta-proj-{tag}",
            {"type": "anomaly", "severity": "critical", "data": {"match_count": 9}, "related": [], "confidence": 0.9},
            org_id=org_b,
        )

        job_id = scheduler.add_job(
            name=f"org_report_{tag}", cron="0 3 * * *", command="report", params={}, enabled=False, org_id=org_a
        )
        try:
            scheduler._execute_job(job_id)
            assert scheduler.jobs[job_id].last_status == "completed"

            row = db.execute_one(
                "SELECT message FROM alerts WHERE alert_type = 'scheduled_report' AND org_id = ? "
                "ORDER BY id DESC LIMIT 1",
                (org_a,),
            )
            assert row is not None, "scheduled report alert was not stored for the job's org"
            report = row["message"]
            assert f"alpha-proj-{tag}" in report
            assert f"beta-proj-{tag}" not in report
            assert "Projects:      1 total" in report  # org-scoped count, not the global registry
        finally:
            scheduler.remove_job(job_id)
            db.execute(f"DELETE FROM intelligence WHERE source_project IN ('alpha-proj-{tag}', 'beta-proj-{tag}')")
            db.execute(f"DELETE FROM alerts WHERE org_id IN ({org_a}, {org_b})")
            db.execute(f"DELETE FROM org_projects WHERE org_id IN ({org_a}, {org_b})")
            db.execute(f"DELETE FROM org_users WHERE org_id IN ({org_a}, {org_b})")
            db.execute(f"DELETE FROM orgs WHERE id IN ({org_a}, {org_b})")
            orchestrator.intel.threat_scores.pop(f"alpha-proj-{tag}", None)
            orchestrator.intel.threat_scores.pop(f"beta-proj-{tag}", None)
