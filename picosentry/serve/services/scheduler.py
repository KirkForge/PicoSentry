import json
import logging
import re
import sched
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import ClassVar

from picosentry.serve.config.settings import settings
from picosentry.serve.database.manager import db

logger = logging.getLogger("picoshogun.Scheduler")

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


class JobScheduler:
    ALLOWED_COMMANDS: ClassVar[set[str]] = {"batch", "run", "report", "backup", "cleanup", "health_check"}

    def __init__(self):
        self.scheduler = sched.scheduler(time.time, time.sleep)
        self.jobs: dict[int, ScheduledJob] = {}
        self.running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
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
            )
            self.jobs[job.id] = job

    def add_job(self, name: str, cron: str, command: str, params: dict | None = None, enabled: bool = True) -> int:
        if command not in self.ALLOWED_COMMANDS:
            raise ValueError(f"Invalid command: {command!r}. Must be one of {sorted(self.ALLOWED_COMMANDS)}")

        if params:
            for key, value in params.items():
                if not isinstance(value, (str, int, float, bool, type(None))):
                    raise ValueError(f"Invalid param {key!r}: values must be strings, numbers, or booleans")

        params_json = json.dumps(params or {})

        job_id = db.execute_insert(
            """
            INSERT INTO scheduled_jobs (name, cron_expression, command, params, enabled)
            VALUES (?, ?, ?, ?, ?)
        """,
            (name, cron, command, params_json, enabled),
        )

        self._load_jobs()

        if self.running:
            self._schedule_job(job_id)

        logger.info("Job added: %s (%s)", name, cron)
        return job_id

    def remove_job(self, job_id: int) -> bool:
        if job_id not in self.jobs:
            return False

        db.execute_insert("DELETE FROM scheduled_jobs WHERE id = ?", (job_id,))
        del self.jobs[job_id]

        logger.info("Job removed: %s", job_id)
        return True

    def enable_job(self, job_id: int) -> bool:
        if job_id not in self.jobs:
            return False

        db.execute("UPDATE scheduled_jobs SET enabled = 1 WHERE id = ?", (job_id,))
        self.jobs[job_id].enabled = True

        if self.running:
            self._schedule_job(job_id)

        return True

    def disable_job(self, job_id: int) -> bool:
        if job_id not in self.jobs:
            return False

        db.execute("UPDATE scheduled_jobs SET enabled = 0 WHERE id = ?", (job_id,))
        self.jobs[job_id].enabled = False
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
        except Exception:
            return None

    def _execute_job(self, job_id: int):
        job = self.jobs.get(job_id)
        if not job:
            return

        logger.info("Executing job: %s", job.name)

        try:
            status = "failed"

            if job.command not in self.ALLOWED_COMMANDS:
                logger.error("Rejected unknown command: %r", job.command)
                db.execute_insert(
                    """
                    UPDATE scheduled_jobs
                    SET last_run = ?, last_status = 'rejected'
                    WHERE id = ?
                """,
                    (datetime.now(), job_id),
                )
                return

            if job.command == "batch":
                import subprocess

                category = str(job.params.get("category", "monitoring"))

                _unsafe_chars = set("/\\;&$`()")
                if any(c in _unsafe_chars for c in category) or "\n" in category or "\r" in category:
                    logger.error("Rejected unsafe category param: %r", category)
                    db.execute_insert(
                        """
                        UPDATE scheduled_jobs
                        SET last_run = ?, last_status = 'rejected'
                        WHERE id = ?
                    """,
                        (datetime.now(), job_id),
                    )
                    return
                result: subprocess.CompletedProcess = subprocess.run(
                    ["bash", "scripts/run_category.sh", category],
                    capture_output=True,
                    text=True,
                    timeout=3600,
                    check=False,
                )
                status = "completed" if result.returncode == 0 else "failed"
                _output = result.stdout + result.stderr

            elif job.command == "run":
                from picosentry.serve.services.orchestrator import orchestrator as _orch

                run_result = _orch.run_project(
                    str(job.params.get("project_id") or ""),
                    int(job.params.get("timeout", 300)),
                )
                status = "completed" if run_result.get("success") else "failed"
                _output = str(run_result)

            elif job.command == "report":
                from picosentry.serve.services.orchestrator import orchestrator as _orch

                _report = _orch.generate_summary_report()
                status = "completed"

            elif job.command == "backup":
                from picosentry.serve.services.backup import BackupManager

                bm = BackupManager()
                backup_result = bm.create_backup()
                status = "completed" if backup_result else "failed"
                _output = str(backup_result)

            elif job.command == "cleanup":
                from picosentry.serve.services.auth import AuthService

                auth = AuthService()
                expired = auth.cleanup_expired_keys()
                from picosentry.serve.services.log_manager import log_manager

                log_manager.auto_rotate()
                from picosentry.serve.services.audit_cleanup import purge_audit_logs

                purge_audit_logs(retention_days=settings.database.audit_retention_days)
                status = "completed"
                _output = f"Cleaned up {expired} expired API keys, rotated logs, purged audit entries"

            db.execute_insert(
                """
                UPDATE scheduled_jobs
                SET last_run = ?, last_status = ?
                WHERE id = ?
            """,
                (datetime.now(), status, job_id),
            )

            job.last_run = datetime.now()
            job.last_status = status

            logger.info("Job %s completed: %s", job.name, status)

        except Exception:
            logger.exception("Job %s failed", job.name)
            db.execute_insert(
                """
                UPDATE scheduled_jobs
                SET last_run = ?, last_status = 'failed'
                WHERE id = ?
            """,
                (datetime.now(), job_id),
            )
            job.last_run = datetime.now()
            job.last_status = "failed"

        if self.running and job.enabled:
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
                self.scheduler.enter(delay, 1, self._execute_job, argument=(job_id,))
                db.execute_insert(
                    """
                    UPDATE scheduled_jobs SET next_run = ? WHERE id = ?
                """,
                    (next_run, job_id),
                )

    def start(self):
        if self.running:
            return

        self.running = True

        for job_id in self.jobs:
            if self.jobs[job_id].enabled:
                self._schedule_job(job_id)

        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

        logger.info("Scheduler started with %s jobs", len(self.jobs))

    def _run(self):
        while self.running:
            self.scheduler.run(blocking=False)
            time.sleep(1)

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Scheduler stopped")

    def get_status(self) -> list[dict]:
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
            }
            for j in self.jobs.values()
        ]


scheduler = JobScheduler()
