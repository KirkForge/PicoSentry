"""Persistent scan job store — JSONL-backed storage for scan results.

Jobs are stored as JSON Lines in ``~/.picodome/jobs.jsonl``. Each line is
a complete JSON object for one job. The store appends on write and
compacts on startup if the file exceeds ``MAX_FILE_SIZE``.

Thread-safe via ``threading.Lock``.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("picodome.daemon.store")

# Schema version for job store files
JOB_STORE_SCHEMA_VERSION = 2  # v2: adds schema_version field to every job

# Default storage directory
DEFAULT_STORE_DIR = Path.home() / ".picodome"

# Maximum file size before compaction (10 MB)
MAX_FILE_SIZE = 10 * 1024 * 1024

# Maximum number of jobs to keep after compaction
MAX_JOBS = 1000


class PersistentScanJobStore:
    """JSONL-backed persistent scan job store.

    - Appends new jobs to the end of the file.
    - Compacts on startup if file exceeds MAX_FILE_SIZE.
    - Thread-safe via lock.
    - Falls back to in-memory store if file I/O fails.
    """

    def __init__(
        self,
        store_dir: Path | None = None,
        max_jobs: int = MAX_JOBS,
    ) -> None:
        self._max_jobs = max_jobs
        self._lock = threading.Lock()
        self._store_dir = store_dir or DEFAULT_STORE_DIR
        self._store_file = self._store_dir / "jobs.jsonl"
        self._jobs: dict[str, dict[str, Any]] = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        """Lazy-load jobs from disk on first access."""
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return  # type: ignore[unreachable]
            try:
                self._load_from_disk()
            except Exception:
                logger.warning("Failed to load job store from disk, starting fresh")
            self._loaded = True

    def _load_from_disk(self) -> None:
        """Load jobs from JSONL file."""
        if not self._store_file.exists():
            return

        # Check file size for compaction
        try:
            file_size = self._store_file.stat().st_size
        except OSError:
            return

        if file_size > MAX_FILE_SIZE:
            self._compact()
            return

        # Load all jobs
        jobs: dict[str, dict[str, Any]] = {}
        try:
            with open(self._store_file, encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        job = json.loads(line)
                        job_id = job.get("job_id")
                        if job_id:
                            jobs[job_id] = job
                    except json.JSONDecodeError:
                        logger.warning("Invalid JSON at line %d in %s", line_num, self._store_file)
        except OSError as e:
            logger.warning("Failed to read job store: %s", e)
            return

        # Keep only the most recent max_jobs
        if len(jobs) > self._max_jobs:
            sorted_jobs = sorted(
                jobs.values(),
                key=lambda j: j.get("created_at", ""),
                reverse=True,
            )
            jobs = {j["job_id"]: j for j in sorted_jobs[: self._max_jobs]}

        self._jobs = jobs
        logger.info("Loaded %d jobs from %s", len(jobs), self._store_file)

    def _compact(self) -> None:
        """Compact the job store by keeping only the most recent max_jobs."""
        logger.info("Compacting job store %s", self._store_file)

        # Load all jobs
        jobs: dict[str, dict[str, Any]] = {}
        try:
            with open(self._store_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        job = json.loads(line)
                        job_id = job.get("job_id")
                        if job_id:
                            jobs[job_id] = job
                    except json.JSONDecodeError:
                        pass
        except OSError:
            return

        # Keep only the most recent max_jobs
        sorted_jobs = sorted(
            jobs.values(),
            key=lambda j: j.get("created_at", ""),
            reverse=True,
        )[: self._max_jobs]

        # Write compacted file
        self._store_dir.mkdir(parents=True, exist_ok=True)
        tmp_file = self._store_file.with_suffix(".jsonl.tmp")
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                for job in sorted_jobs:
                    f.write(json.dumps(job, sort_keys=True, default=str) + "\n")
            tmp_file.replace(self._store_file)
            logger.info("Compacted job store: %d → %d jobs", len(jobs), len(sorted_jobs))
        except OSError as e:
            logger.warning("Failed to compact job store: %s", e)
            try:
                tmp_file.unlink()
            except OSError:
                pass

        self._jobs = {j["job_id"]: j for j in sorted_jobs}

    def _append_to_disk(self, job: dict[str, Any]) -> None:
        """Append a single job to the JSONL file."""
        self._store_dir.mkdir(parents=True, exist_ok=True)
        try:
            with open(self._store_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(job, sort_keys=True, default=str) + "\n")
        except OSError as e:
            logger.warning("Failed to persist job %s: %s", job.get("job_id", "?"), e)

    def add(self, job_id: str, command: list[str], actor: str) -> dict[str, Any]:
        """Add a new job and persist it.

        Args:
            job_id: Unique job identifier.
            command: Command that was submitted.
            actor: Authenticated actor (token prefix).

        Returns:
            The job dict.
        """
        self._ensure_loaded()
        job = {
            "job_id": job_id,
            "command": command,
            "actor": actor,
            "status": "pending",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "completed_at": None,
            "result": None,
            "error": None,
            "schema_version": JOB_STORE_SCHEMA_VERSION,
        }
        with self._lock:
            self._jobs[job_id] = job
            self._append_to_disk(job)
        return job

    def update(self, job_id: str, **kwargs: Any) -> dict[str, Any] | None:
        """Update a job's fields and persist.

        Args:
            job_id: Job identifier.
            **kwargs: Fields to update (status, result, error, etc.)

        Returns:
            Updated job dict, or None if not found.
        """
        self._ensure_loaded()
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            job.update(kwargs)
            if "status" in kwargs and kwargs["status"] in ("completed", "failed"):
                job["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            # Re-write the entire file on update (simple but correct)
            self._rewrite_disk()
            return job

    def get(self, job_id: str) -> dict[str, Any] | None:
        """Get a job by ID."""
        self._ensure_loaded()
        with self._lock:
            return self._jobs.get(job_id)

    def list_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        """List recent jobs, newest first."""
        self._ensure_loaded()
        with self._lock:
            jobs = sorted(
                self._jobs.values(),
                key=lambda j: j.get("created_at", ""),
                reverse=True,
            )
            return jobs[:limit]

    def _rewrite_disk(self) -> None:
        """Rewrite the entire job store file."""
        self._store_dir.mkdir(parents=True, exist_ok=True)
        tmp_file = self._store_file.with_suffix(".jsonl.tmp")
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                for job in self._jobs.values():
                    f.write(json.dumps(job, sort_keys=True, default=str) + "\n")
            tmp_file.replace(self._store_file)
        except OSError as e:
            logger.warning("Failed to rewrite job store: %s", e)
            try:
                tmp_file.unlink()
            except OSError:
                pass
