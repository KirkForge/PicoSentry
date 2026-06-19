from __future__ import annotations

import contextlib
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("picodome.daemon.store")


JOB_STORE_SCHEMA_VERSION = 2  # v2: adds schema_version field to every job


DEFAULT_STORE_DIR = Path.home() / ".picodome"


MAX_FILE_SIZE = 10 * 1024 * 1024


MAX_JOBS = 1000


class PersistentScanJobStore:
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
        if not self._store_file.exists():
            return

        try:
            file_size = self._store_file.stat().st_size
        except OSError:
            return

        if file_size > MAX_FILE_SIZE:
            self._compact()
            return

        jobs: dict[str, dict[str, Any]] = {}
        try:
            with open(self._store_file, encoding="utf-8") as f:
                for line_num, raw_line in enumerate(f, 1):
                    line = raw_line.strip()
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
        logger.info("Compacting job store %s", self._store_file)

        jobs: dict[str, dict[str, Any]] = {}
        try:
            with open(self._store_file, encoding="utf-8") as f:
                for raw_line in f:
                    line = raw_line.strip()
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

        sorted_jobs = sorted(
            jobs.values(),
            key=lambda j: j.get("created_at", ""),
            reverse=True,
        )[: self._max_jobs]

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
            with contextlib.suppress(OSError):
                tmp_file.unlink()

        self._jobs = {j["job_id"]: j for j in sorted_jobs}

    def _append_to_disk(self, job: dict[str, Any]) -> None:
        self._store_dir.mkdir(parents=True, exist_ok=True)
        try:
            with open(self._store_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(job, sort_keys=True, default=str) + "\n")
        except OSError as e:
            logger.warning("Failed to persist job %s: %s", job.get("job_id", "?"), e)

    def add(self, job_id: str, command: list[str], actor: str) -> dict[str, Any]:
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
        self._ensure_loaded()
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            job.update(kwargs)
            if "status" in kwargs and kwargs["status"] in ("completed", "failed"):
                job["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            self._rewrite_disk()
            return job

    def get(self, job_id: str) -> dict[str, Any] | None:
        self._ensure_loaded()
        with self._lock:
            return self._jobs.get(job_id)

    def list_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        self._ensure_loaded()
        with self._lock:
            jobs = sorted(
                self._jobs.values(),
                key=lambda j: j.get("created_at", ""),
                reverse=True,
            )
            return jobs[:limit]

    def _rewrite_disk(self) -> None:
        self._store_dir.mkdir(parents=True, exist_ok=True)
        tmp_file = self._store_file.with_suffix(".jsonl.tmp")
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                f.writelines(json.dumps(job, sort_keys=True, default=str) + "\n" for job in self._jobs.values())
            tmp_file.replace(self._store_file)
        except OSError as e:
            logger.warning("Failed to rewrite job store: %s", e)
            with contextlib.suppress(OSError):
                tmp_file.unlink()
