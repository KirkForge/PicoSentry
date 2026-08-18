import contextlib
import json
import logging
import re
import sched
import sqlite3
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import ClassVar

from picosentry.serve.config.settings import settings
from picosentry.serve.database.manager import db
from picosentry.serve.services.event_bus import worker_identity

logger = logging.getLogger("picoshogun.Scheduler")

# The batch job's script lives at the repo root, not the scheduler's CWD —
# resolving module-relative keeps it working under uvicorn/systemd/any cwd.
_REPO_ROOT = Path(__file__).resolve().parents[3]

try:
    import psycopg2 as _psycopg2
except ImportError:
    _psycopg2 = None

# DB failures the lease protocol tolerates per tick (stand down + retry).
_DB_SOFT_ERRORS: tuple[type[BaseException], ...] = (OSError, RuntimeError, ValueError, sqlite3.Error) + (
    (_psycopg2.Error,) if _psycopg2 is not None else ()
)
# Unique-violation shapes from racing INSERTs (see _insert_job_atomic).
_INTEGRITY_ERRORS: tuple[type[BaseException], ...] = (sqlite3.IntegrityError,) + (
    (_psycopg2.IntegrityError,) if _psycopg2 is not None else ()
)


def _utcnow() -> datetime:
    """Single clock seam: tests patch this to move lease time deterministically."""
    return datetime.now(timezone.utc)


class SchedulerJobConflict(ValueError):
    """A job with this name exists in the same org with a different config."""


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
        # job id -> its queued scheduler entries; _schedule_job
        # cancel-and-replaces so boot/toggle cycles can never double-fire.
        self._queued: dict[int, list[sched.Event]] = {}
        # Cross-worker leader lease: only the lease holder runs the sched
        # loop; standbys poll for takeover. Manual trigger_job() is explicit
        # user intent and still dispatches on any worker.
        self.worker_id = worker_identity()
        self.lease_ttl = settings.multiworker.scheduler_lease_ttl_seconds
        self._leader = False
        self._tick_sleep = 1.0
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

        # Names are globally unique today (scheduled_jobs.name UNIQUE); the
        # org check below only decides whose request wins. Per-org name
        # scoping (like webhooks migration 20) is the upgrade path.
        existing = db.execute_one(
            "SELECT id, org_id, cron_expression, command, params FROM scheduled_jobs WHERE name = ?", (name,)
        )
        if existing:
            if existing.get("org_id") != org_id:
                raise ValueError(f"Job name already in use by another organization: {name!r}")
            if (
                existing["cron_expression"] != cron
                or existing["command"] != command
                or json.loads(existing["params"]) != (params or {})
            ):
                raise SchedulerJobConflict(
                    f"Job {name!r} already exists with a different config; update it or choose another name"
                )
            job_id = existing["id"]
        else:
            if self._get_next_run(cron) is None:
                raise ValueError(f"Invalid cron expression: {cron!r}")
            job_id = self._insert_job_atomic(name, cron, command, params_json, enabled, org_id)

        with self._lock:
            self._load_jobs()
            if self.running:
                self._schedule_job(job_id)

        logger.info("Job added: %s (%s)", name, cron)
        return job_id

    def _insert_job_atomic(
        self, name: str, cron: str, command: str, params_json: str, enabled: bool, org_id: int | None
    ) -> int:
        """SELECT+INSERT under BEGIN IMMEDIATE (WO5.0.0-031).

        The boot-time lifespan add_job()s from two workers booting
        simultaneously raced between the name SELECT and the INSERT, and the
        loser died in lifespan startup on the name UNIQUE constraint
        (verified with a real 2-worker uvicorn boot). BEGIN IMMEDIATE
        serializes sqlite writers so the second boot's in-transaction SELECT
        sees the winner's row; on postgres the loser's INSERT fails on the
        unique index after the winner commits and is retried as a read.
        """
        try:
            with db.transaction(immediate=True) as conn:
                row = db.execute_on(conn, "SELECT id FROM scheduled_jobs WHERE name = ?", (name,))
                if row:
                    return row[0]["id"]
                db.execute_on(
                    conn,
                    "INSERT INTO scheduled_jobs (name, cron_expression, command, params, enabled, org_id) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (name, cron, command, params_json, enabled, org_id),
                )
                row = db.execute_on(conn, "SELECT id FROM scheduled_jobs WHERE name = ?", (name,))
                return row[0]["id"]
        except _INTEGRITY_ERRORS:
            existing = db.execute_one("SELECT id FROM scheduled_jobs WHERE name = ?", (name,))
            if existing:
                return existing["id"]
            raise

    def remove_job(self, job_id: int) -> bool:
        with self._lock:
            if job_id not in self.jobs:
                return False
            del self.jobs[job_id]
            self._cancel_queued(job_id)

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
            # A queued entry for a now-disabled job must not fire.
            self._cancel_queued(job_id)

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

                report = _orch.generate_summary_report(org_id=job.org_id)
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

    def _cancel_queued(self, job_id: int) -> None:
        """Cancel (and forget) every queued scheduler entry for *job_id*."""
        with contextlib.suppress(ValueError):  # entry already fired
            for event in self._queued.pop(job_id, []):
                self.scheduler.cancel(event)

    def _schedule_job(self, job_id: int):
        job = self.jobs.get(job_id)
        if not job or not job.enabled:
            return

        next_run = self._get_next_run(job.cron_expression)
        if next_run:
            # Cancel-and-replace: boot order (start() then lifespan add_job)
            # and update/enable cycles re-enter jobs; without the cancel every
            # cycle permanently doubled the queue entry (double nightly
            # backups, purges, probes).
            self._cancel_queued(job_id)
            job.next_run = next_run
            delay = (next_run - datetime.now()).total_seconds()
            if delay > 0:
                event = self.scheduler.enter(delay, 1, self._dispatch_job, argument=(job_id,))
                self._queued[job_id] = [event]
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

    def _try_acquire_lease(self) -> bool:
        """Acquire-or-renew the cross-worker leader lease, atomically.

        One conditional UPDATE: the rowcount IS the protocol answer. A
        standby can take over once the holder's expiry passed (holder
        crashed without releasing); the holder renews because its own id
        satisfies the WHERE regardless of expiry.
        # ponytail: expiry-based lease, not pg advisory locks — one SQL
        # statement on both backends; advisory locks upgrade path if lease
        # churn across many workers ever shows up in metrics.
        """
        now = _utcnow()
        rows = db.execute_update(
            "UPDATE scheduler_leases SET holder = ?, expires_at = ? "
            "WHERE lease_key = ? AND (holder = ? OR expires_at < ?)",
            (self.worker_id, now + timedelta(seconds=self.lease_ttl), "scheduler", self.worker_id, now),
        )
        return rows >= 1

    def _release_lease(self) -> None:
        try:
            db.execute_update(
                "UPDATE scheduler_leases SET holder = NULL, expires_at = ? WHERE lease_key = ? AND holder = ?",
                (_utcnow() - timedelta(seconds=1), "scheduler", self.worker_id),
            )
        except _DB_SOFT_ERRORS:
            logger.debug("Scheduler lease release failed (lease will expire)", exc_info=True)

    def _reschedule_all(self) -> None:
        """Drop every queued entry and recompute from cron.

        Called on leadership transitions: the previous leader's in-memory
        queue may hold overdue entries that a fresh next_run computation
        must replace, or a takeover would double-fire the boundary job.
        """
        with self._lock:
            for job_id in list(self._queued):
                self._cancel_queued(job_id)
            for job_id in list(self.jobs):
                if self.jobs[job_id].enabled:
                    self._schedule_job(job_id)

    def _run(self):
        lease_failures = 0
        while True:
            with self._lock:
                if not self.running:
                    break
            try:
                leader = self._try_acquire_lease()
            except _DB_SOFT_ERRORS:
                # DB unavailable: stand down rather than guess; the lease
                # expires and another worker takes over. Missed ticks are
                # skipped, not fired-catch-up (documented ceiling).
                leader = False
                lease_failures += 1
                if lease_failures == 1 or lease_failures % 30 == 0:
                    logger.warning("Scheduler lease check failed; standing down", exc_info=True)
            else:
                lease_failures = 0
            if leader != self._leader:
                if leader:
                    self._reschedule_all()
                    logger.info("Scheduler leadership acquired by %s", self.worker_id)
                else:
                    for job_id in list(self._queued):
                        self._cancel_queued(job_id)
                    logger.info("Scheduler leadership lost by %s", self.worker_id)
                self._leader = leader
            if leader:
                self.scheduler.run(blocking=False)
            time.sleep(self._tick_sleep)

    def stop(self):
        with self._lock:
            self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        self._release_lease()
        self._leader = False
        logger.info("Scheduler stopped")

    def is_leader(self) -> bool:
        return self._leader

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
                "leader": self._leader,
            }
            for j in jobs
        ]


scheduler = JobScheduler()
