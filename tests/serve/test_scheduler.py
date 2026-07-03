"""Focused unit tests for the PicoShogun job scheduler.

These tests cover security-relevant validation that is hard to exercise
through the HTTP API alone (e.g. batch category allowlist enforcement).
"""

import time

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


class TestSchedulerHardening:
    """Scheduler must log parse failures instead of silently returning None."""

    def test_invalid_cron_expression_logs_and_returns_none(self, caplog):
        import logging

        with caplog.at_level(logging.WARNING, logger="picoshogun.scheduler"):
            result = scheduler._get_next_run("not-a-cron")

        assert result is None
        assert any("Invalid cron expression" in r.message for r in caplog.records)
