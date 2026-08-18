import json
import logging
import re
import sched
import sqlite3
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import ClassVar

from picosentry.serve.database.manager import db

logger = logging.getLogger("picoshogun.Scheduler")

# The batch job's script lives at the repo root, not the scheduler's CWD —
# resolving module-relative keeps it working under uvicorn/systemd/any cwd.
_REPO_ROOT = Path(__file__).resolve().parents[3]

_JOB_EXECUTE_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
    ImportError,
    sqlite3.Error,
    subprocess.SubprocessError,
)

try:
    from croniter import croniter

    HAS_CRONITER = True
except ImportError:
    HAS_CRONITER = False


@dataclass
class ScheduledJob:
    id: int
    name: str
    cron_expression: str
    command: str  # 'batch', 'run', 'report', 'backup'
    params: dict
    enabled: bool
    next_run: datetime | None
    last_run: datetime | None
    last_status: str | None
    org_id: int | None = None


class JobScheduler:
    """Schedules and executes recurring jobs using cron expressions."""

    ALLOWED_COMMANDS: ClassVar[set[str]] = {"batch", "run", "report", "backup", "cleanup", "health_check"}
    ALLOWED_CATEGORIES: ClassVar[set[str]] = {
        "monitoring",
        "audit",
        "security",
        "maintenance",
        "health",
        "backup",
        "report",
    }

    def __init__(self):
        self.scheduler = sched.scheduler(time.time, time.sleep)
        self.jobs: dict[int, ScheduledJob] = {}
        self.running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._slow_running: set[int] = set()
        self._load_jobs()

    def _load_jobs(self):
        rows = db.execute("SELECT * FROM scheduled_jobs")
        for row in rows:
            job = ScheduledJob(
                id=row["id"],
                name=row["name"],
                cron_expression=row["cron_expression"],
                command=row["command"],
                params=json.loads(row["params"]),
                enabled=row["enabled"],
                next_run=row["next_run"],
                last_run=row["last_run"],
                last_status=row["last_status"],
                org_id=row.get("org_id"),
            )
            self.jobs[job.id] = job

    def add_job(
        self,
        name: str,
        cron: str,
        command: str,
        params: dict | None = None,
        enabled: bool = True,
        org_id: int | None = None,
    ) -> int:
        if command not in self.ALLOWED_COMMANDS:
            raise ValueError(f"Invalid command: {command!r}. Must be one of {sorted(self.ALLOWED_COMMANDS)}")

        if params:
            for key, value in params.items():
                if not isinstance(value, (str, int, float, bool, type(None))):
                    raise ValueError(f"Invalid param {key!r}: values must be strings, numbers, or booleans")

        params_json = json.dumps(params or {})

        existing = db.execute_one("SELECT id, org_id FROM scheduled_jobs WHERE name = ?", (name,))
        if existing:
            if existing.get("org_id") != org_id:
                raise ValueError(f"Job name already in use by another organization: {name!r}")
            job_id = existing["id"]
        else:
            if self._get_next_run(cron) is None:
                raise ValueError(f"Invalid cron expression: {cron!r}")
            job_id = db.execute_insert(
                """
                INSERT INTO scheduled_jobs (name, cron_expression, command, params, enabled, org_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (name, cron, command, params_json, enabled, org_id),
            )

        with self._lock:
            self._load_jobs()
            if self.running:
                self._schedule_job(job_id)

        logger.info("Job added: %s (%s)", name, cron)
        return job_id

    def remove_job(self, job_id: int) -> bool:
        with self._lock:
            if job_id not in self.jobs:
                return False
            del self.jobs[job_id]

        db.execute_insert("DELETE FROM scheduled_jobs WHERE id = ?", (job_id,))
        logger.info("Job removed: %s", job_id)
        return True

    def enable_job(self, job_id: int) -> bool:
        with self._lock:
            if job_id not in self.jobs:
                return False
            self.jobs[job_id].enabled = True
            if self.running:
                self._schedule_job(job_id)

        db.execute("UPDATE scheduled_jobs SET enabled = 1 WHERE id = ?", (job_id,))
        return True

    def disable_job(self, job_id: int) -> bool:
        with self._lock:
            if job_id not in self.jobs:
                return False
            self.jobs[job_id].enabled = False

        db.execute("UPDATE scheduled_jobs SET enabled = 0 WHERE id = ?", (job_id,))
        return True

    def update_job(self, job_id: int, cron: str | None = None, params: dict | None = None) -> bool:
        """Update a job's cron expression and/or params in place.

        Recovers a job whose stored cron/params went bad (e.g. a rejected
        category) without delete + re-create, keeping the job id stable.
        """
        with self._lock:
            job = self.jobs.get(job_id)
            if job is None:
                return False

        if cron is not None:
            if self._get_next_run(cron) is None:
                raise ValueError(f"Invalid cron expression: {cron!r}")
            db.execute("UPDATE scheduled_jobs SET cron_expression = ? WHERE id = ?", (cron, job_id))
        if params is not None:
            for key, value in params.items():
                if not isinstance(value, (str, int, float, bool, type(None))):
                    raise ValueError(f"Invalid param {key!r}: values must be strings, numbers, or booleans")
            db.execute("UPDATE scheduled_jobs SET params = ? WHERE id = ?", (json.dumps(params), job_id))

        with self._lock:
            self._load_jobs()
            if self.running:
                self._schedule_job(job_id)
        return True

    def trigger_job(self, job_id: int) -> bool:
        """Dispatch a job immediately (respects the skip-while-running guard)."""
        with self._lock:
            job = self.jobs.get(job_id)
            if job is None or not job.enabled:
                return False
        self._dispatch_job(job_id)
        return True

    def _get_next_run(self, cron_expression: str) -> datetime | None:
        if not HAS_CRONITER:
            match = re.match(r"every\s+(\d+)\s+(minute|hour|day)", cron_expression, re.IGNORECASE)
            if match:
                val = int(match.group(1))
                unit = match.group(2)
                now = datetime.now()
                if unit == "minute":
                    return now + timedelta(minutes=val)
                if unit == "hour":
                    return now + timedelta(hours=val)
                if unit == "day":
                    return now + timedelta(days=val)
            return None

        try:
            itr = croniter(cron_expression, datetime.now())
            return itr.get_next(datetime)
        except (ValueError, TypeError, KeyError):
            logger.warning("Invalid cron expression '%s'; cannot compute next run", cron_expression)
            return None

    def _validate_category(self, category: str) -> bool:
        """Return True if *category* is a known-good batch category.

        The allowlist replaces a fragile character blacklist and prevents
        command-injection through the ``category`` job param.
        """
        return category in self.ALLOWED_CATEGORIES

    def _org_for_run(self, job_id: int, project_id: str) -> int | None:
        """Resolve the org a scheduler-triggered run must be stamped with.

        Unstamped (org=None) run events are WS-broadcast to every org; the
        job's owning org — or the project's org_projects mapping for legacy
        unowned jobs — closes that tenancy leak at its source.
        """
        with self._lock:
            job = self.jobs.get(job_id)
            if job is not None and job.org_id is not None:
                return job.org_id
        row = db.execute_one(
            "SELECT org_id FROM org_projects WHERE project_id = ? ORDER BY id LIMIT 1",
            (project_id,),
        )
        return row["org_id"] if row else None

    def _dispatch_job(self, job_id: int):
        """Scheduler-loop entry point: keeps slow jobs off the scheduler thread.

        Batch jobs run for up to an hour and health checks probe SMTP with a
        5s timeout; executing them inline starved every minute-job on the
        single scheduler thread (head-of-line blocking). Slow jobs run on
        their own daemon thread — a still-running job skips (with a warning)
        instead of stacking when its next trigger fires.
        # ponytail: daemon threads, not a ThreadPoolExecutor — futures workers
        # are joined at interpreter exit (3.9+), so an in-flight 3600s batch
        # would block process shutdown; per-job guard bounds concurrency.
        """
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            # Slow commands run off the scheduler thread; see _dispatch_job.
            slow = job.command in ("batch", "health_check")
            if slow and job_id in self._slow_running:
                logger.warning("Job %s (%s) still running; skipping trigger", job_id, job.name)
                return
            if slow:
                self._slow_running.add(job_id)

        if not slow:
            self._execute_job(job_id)
            return

        thread = threading.Thread(target=self._run_slow_job, args=(job_id,), daemon=True)
        thread.start()

    def _run_slow_job(self, job_id: int):
        try:
            self._execute_job(job_id)
        finally:
            with self._lock:
                self._slow_running.discard(job_id)

    def _execute_job(self, job_id: int):
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            command = job.command
            name = job.name
            params = job.params

        logger.info("Executing job: %s", name)

        try:
            status = "failed"
            _output: str | None = None

            # Rejected jobs fall through to the shared status update +
            # reschedule tail: a bad param must not permanently kill the job.
            if command not in self.ALLOWED_COMMANDS:
                logger.error("Rejected unknown command: %r", command)
                status = "rejected"

            elif command == "batch":
                import subprocess

                category = str(params.get("category", "monitoring"))

                if not self._validate_category(category):
                    logger.error("Rejected unknown category param: %r", category)
                    status = "rejected"
                else:
                    script = _REPO_ROOT / "scripts" / "run_category.sh"
                    if not script.exists():
                        logger.error("Batch script not found at %s", script)
                        status = "failed"
                        _output = f"batch script missing: {script}"
                    else:
                        result: subprocess.CompletedProcess = subprocess.run(
                            ["bash", str(script), category],
                            capture_output=True,
                            text=True,
                            timeout=3600,
                            check=False,
                            cwd=str(_REPO_ROOT),
                        )
                        status = "completed" if result.returncode == 0 else "failed"
                        _output = result.stdout + result.stderr

            elif command == "run":
                from picosentry.serve.services.orchestrator import orchestrator as _orch

                project_id = str(params.get("project_id") or "")
                run_result = _orch.run_project(
                    project_id,
                    int(params.get("timeout", 300)),
                    org_id=self._org_for_run(job_id, project_id),
                )
                status = "completed" if run_result.get("success") else "failed"
                _output = str(run_result)

            elif command == "report":
                from picosentry.serve.services.orchestrator import orchestrator as _orch

                report = _orch.generate_summary_report()
                # Delivery: the alert hub fans the report out to the
                # configured channels and its alerts-table row is the
                # stored, queryable copy of the output.
                _orch.alerts.send("system", "scheduled_report", "info", report, org_id=job.org_id)
                status = "completed"
                _output = report

            elif command == "health_check":
                from picosentry.serve.services.orchestrator import orchestrator as _orch

                checks = _orch.get_health_checks()
                status = "completed" if checks else "failed"
                _output = f"{len(checks)} health checks recorded"

            elif command == "backup":
                from picosentry.serve.services.backup import BackupManager

                bm = BackupManager()
                backup_result = bm.create_backup()
                status = "completed" if backup_result else "failed"
                _output = str(backup_result)

            elif command == "cleanup":
                from picosentry.serve.services.auth import AuthService

                auth = AuthService()
                expired = auth.cleanup_expired_keys()
                from picosentry.serve.services.log_manager import log_manager

                log_manager.auto_rotate()
                from picosentry.serve.services.audit_cleanup import purge_audit_logs

                # Per-severity retention policy; the flat retention_days override
                # is admin-endpoint-only — it would delete critical audit history
                # at the same cutoff as low.
                purge_audit_logs()
                auth.purge_expired_revocations()
                status = "completed"
                _output = f"Cleaned up {expired} expired API keys, rotated logs, purged audit entries"

            now = datetime.now()
            db.execute_insert(
                """
                UPDATE scheduled_jobs
                SET last_run = ?, last_status = ?
                WHERE id = ?
            """,
                (now, status, job_id),
            )

            with self._lock:
                job.last_run = now
                job.last_status = status

            logger.info("Job %s completed: %s", name, status)

        except _JOB_EXECUTE_ERRORS:
            logger.exception("Job %s failed", name)
            now = datetime.now()
            db.execute_insert(
                """
                UPDATE scheduled_jobs
                SET last_run = ?, last_status = 'failed'
                WHERE id = ?
            """,
                (now, job_id),
            )
            with self._lock:
                job.last_run = now
                job.last_status = "failed"

        with self._lock:
            if self.running and job_id in self.jobs and self.jobs[job_id].enabled:
                self._schedule_job(job_id)

    def _schedule_job(self, job_id: int):
        job = self.jobs.get(job_id)
        if not job or not job.enabled:
            return

        next_run = self._get_next_run(job.cron_expression)
        if next_run:
            job.next_run = next_run
            delay = (next_run - datetime.now()).total_seconds()
            if delay > 0:
                self.scheduler.enter(delay, 1, self._dispatch_job, argument=(job_id,))
                db.execute_insert(
                    """
                    UPDATE scheduled_jobs SET next_run = ? WHERE id = ?
                """,
                    (next_run, job_id),
                )

    def start(self):
        with self._lock:
            if self.running:
                return
            self.running = True
            for job_id in list(self.jobs):
                if self.jobs[job_id].enabled:
                    self._schedule_job(job_id)
            job_count = len(self.jobs)

        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

        logger.info("Scheduler started with %s jobs", job_count)

    def _run(self):
        while True:
            with self._lock:
                if not self.running:
                    break
            self.scheduler.run(blocking=False)
            time.sleep(1)

    def stop(self):
        with self._lock:
            self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Scheduler stopped")

    def get_status(self) -> list[dict]:
        with self._lock:
            jobs = list(self.jobs.values())
        return [
            {
                "id": j.id,
                "name": j.name,
                "cron": j.cron_expression,
                "command": j.command,
                "enabled": j.enabled,
                "next_run": j.next_run.isoformat() if j.next_run else None,
                "last_run": j.last_run.isoformat() if j.last_run else None,
                "last_status": j.last_status,
                "org_id": j.org_id,
            }
            for j in jobs
        ]


scheduler = JobScheduler()
