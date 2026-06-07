"""In-memory scan job store.

Extracted in v2.1.0 (refactor) from ``picosentry/sandbox/daemon/server.py``.

Matches the interface of :class:`PersistentScanJobStore` so the handler
can treat both stores uniformly.
"""
from __future__ import annotations

import time
from typing import Any


class ScanJobStore:
    """In-memory store of recent scan jobs (bounded)."""

    def __init__(self, max_jobs: int = 1000) -> None:
        self._jobs: dict[str, dict[str, Any]] = {}
        self._max_jobs = max_jobs

    def add(self, job_id: str, command: list[str], actor: str) -> dict[str, Any]:
        job: dict[str, Any] = {
            "job_id": job_id,
            "command": command,
            "actor": actor,
            "status": "pending",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "completed_at": None,
            "result": None,
            "error": None,
        }
        self._jobs[job_id] = job

        if len(self._jobs) > self._max_jobs:
            oldest_key = min(self._jobs, key=lambda k: str(self._jobs[k].get("created_at", "")))
            del self._jobs[oldest_key]

        return job

    def update(self, job_id: str, **kwargs: Any) -> dict[str, Any] | None:
        job = self._jobs.get(job_id)
        if job is None:
            return None
        job.update(kwargs)
        return job

    def get(self, job_id: str) -> dict[str, Any] | None:
        return self._jobs.get(job_id)

    def list_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        jobs = sorted(self._jobs.values(), key=lambda j: str(j.get("created_at", "")), reverse=True)
        return jobs[:limit]


__all__ = ["ScanJobStore"]
