from __future__ import annotations

import contextlib
import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from picosentry.sandbox.daemon.store import JOB_STORE_SCHEMA_VERSION


ALLOWED_COLUMNS = frozenset(
    {
        "job_id",
        "command",
        "actor",
        "status",
        "created_at",
        "completed_at",
        "result",
        "error",
        "tenant_id",
        "schema_version",
    }
)

logger = logging.getLogger("picodome.daemon.sqlite_store")

_DEFAULT_DB_PATH = Path.home() / ".picodome" / "jobs.db"

_SCHEMA_V2 = f"""
CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    command TEXT NOT NULL,
    actor TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    completed_at TEXT,
    result TEXT,
    error TEXT,
    tenant_id TEXT,
    schema_version INTEGER NOT NULL DEFAULT {JOB_STORE_SCHEMA_VERSION}
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_actor ON jobs(actor);
CREATE INDEX IF NOT EXISTS idx_jobs_tenant ON jobs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at);
"""


class SQLiteScanJobStore:
    def __init__(
        self,
        db_path: Path | str | None = None,
        max_jobs: int = 10000,
    ) -> None:
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self._max_jobs = max_jobs
        self._lock = threading.Lock()
        self._local = threading.local()
        self._initialized = False

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
            self._local.conn = conn
        return self._local.conn

    def _ensure_schema(self) -> None:
        if self._initialized:
            return
        with self._lock:
            if self._initialized:
                return  # type: ignore[unreachable]
            conn = self._get_conn()
            conn.executescript(_SCHEMA_V2)
            conn.commit()
            self._initialized = True
            logger.info("SQLite job store initialized at %s", self._db_path)

    def add(self, job_id: str, command: list[str], actor: str) -> dict[str, Any]:
        self._ensure_schema()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        job = {
            "job_id": job_id,
            "command": command,
            "actor": actor,
            "status": "pending",
            "created_at": now,
            "completed_at": None,
            "result": None,
            "error": None,
            "schema_version": JOB_STORE_SCHEMA_VERSION,
        }

        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """INSERT INTO jobs (job_id, command, actor, status, created_at, result, error, schema_version)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        job_id,
                        json.dumps(command),
                        actor,
                        "pending",
                        now,
                        "",
                        "",
                        JOB_STORE_SCHEMA_VERSION,
                    ),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                logger.warning("Job %s already exists, updating", job_id)
                conn.execute(
                    """UPDATE jobs SET command=?, actor=?, status=?, created_at=?
                       WHERE job_id=?""",
                    (json.dumps(command), actor, "pending", now, job_id),
                )
                conn.commit()

        self._prune_old_jobs()

        return job

    def update(self, job_id: str, **kwargs: Any) -> dict[str, Any] | None:

        invalid_keys = set(kwargs.keys()) - ALLOWED_COLUMNS
        if invalid_keys:
            raise ValueError(f"Invalid column(s) for update: {invalid_keys}. Allowed: {sorted(ALLOWED_COLUMNS)}")

        self._ensure_schema()
        with self._lock:
            conn = self._get_conn()

            set_clauses = []
            values = []
            for key, value in kwargs.items():
                if key == "command" and isinstance(value, list):
                    set_clauses.append(f"{key} = ?")
                    values.append(json.dumps(value))
                elif value is None:
                    set_clauses.append(f"{key} = ?")
                    values.append("")
                else:
                    set_clauses.append(f"{key} = ?")
                    values.append(str(value))

            if "status" in kwargs and kwargs["status"] in ("completed", "failed"):
                set_clauses.append("completed_at = ?")
                values.append(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

            if not set_clauses:
                return self.get(job_id)

            values.append(job_id)
            query = f"UPDATE jobs SET {', '.join(set_clauses)} WHERE job_id = ?"
            cursor = conn.execute(query, values)
            conn.commit()

            if cursor.rowcount == 0:
                return None

        return self.get(job_id)

    def get(self, job_id: str) -> dict[str, Any] | None:
        self._ensure_schema()
        with self._lock:
            conn = self._get_conn()
        cursor = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,))
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    def list_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        self._ensure_schema()
        with self._lock:
            conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        return [self._row_to_dict(row) for row in cursor.fetchall()]

    def count(self) -> int:
        self._ensure_schema()
        conn = self._get_conn()
        cursor = conn.execute("SELECT COUNT(*) FROM jobs")
        return cursor.fetchone()[0]

    def prune(self, max_jobs: int | None = None) -> int:
        self._ensure_schema()
        limit = max_jobs or self._max_jobs
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute(
                """DELETE FROM jobs WHERE job_id IN (
                    SELECT job_id FROM jobs ORDER BY created_at ASC
                    LIMIT (SELECT COUNT(*) FROM jobs) - ?
                )""",
                (limit,),
            )
            conn.commit()
            deleted = cursor.rowcount
            if deleted > 0:
                logger.info("Pruned %d old jobs from SQLite store", deleted)
            return deleted

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None

    @property
    def db_path(self) -> Path:
        return self._db_path

    def _prune_old_jobs(self) -> None:
        total = self.count()
        if total > self._max_jobs:
            self.prune()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)

        if "command" in d and isinstance(d["command"], str):
            with contextlib.suppress(json.JSONDecodeError):
                d["command"] = json.loads(d["command"])

        for field in ("completed_at", "result", "error"):
            if d.get(field) == "":
                d[field] = None
        return d

    @classmethod
    def from_env(cls, max_jobs: int = 10000) -> SQLiteScanJobStore:
        db_path = os.environ.get("PICODOME_SQLITE_PATH")
        return cls(db_path=Path(db_path) if db_path else None, max_jobs=max_jobs)
