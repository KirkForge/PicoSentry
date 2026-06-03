"""Redis-backed scan job store — horizontal scale shared state.

When running multiple PicoDome replicas behind a load balancer,
in-memory job state is not shared. This Redis-backed store
provides shared state accessible from all replicas.

Configuration:
  PICODOME_REDIS_URL — Redis connection URL (default: redis://localhost:6379/0)

Falls back to PersistentScanJobStore when Redis is unavailable.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

logger = logging.getLogger("picodome.daemon.redis_store")

_DEFAULT_REDIS_URL = "redis://localhost:6379/0"
_JOB_KEY_PREFIX = "picodome:job:"
_JOB_LIST_KEY = "picodome:jobs:recent"

# Allowed columns for update() — prevents arbitrary field injection
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
    }
)


class RedisScanJobStore:
    """Redis-backed scan job store for horizontal scaling.

    Stores each job as a Redis hash under ``picodome:job:<job_id>``.
    Maintains a sorted set of recent job IDs for list_recent queries.

    Thread-safe: Redis connections are thread-safe by default.

    Args:
        redis_url: Redis connection URL.
        max_jobs: Maximum jobs to keep in the recent list.
    """

    def __init__(
        self,
        redis_url: str | None = None,
        max_jobs: int = 1000,
    ) -> None:
        self._redis_url = redis_url or os.environ.get("PICODOME_REDIS_URL", _DEFAULT_REDIS_URL)
        self._max_jobs = max_jobs
        self._client = None
        self._available = False

    def _get_client(self):
        """Lazy-init Redis client."""
        if self._client is not None:
            return self._client

        try:
            import redis

            self._client = redis.from_url(self._redis_url, decode_responses=True)
            # Test connection
            self._client.ping()
            self._available = True
            logger.info("Redis connected: %s", self._redis_url)
        except ImportError:
            logger.warning("Redis package not installed, RedisScanJobStore unavailable")
            self._available = False
        except Exception as exc:
            logger.warning("Redis connection failed: %s", exc)
            self._available = False
            self._client = None

        return self._client

    @property
    def available(self) -> bool:
        """Check if Redis is available."""
        if self._client is None:
            self._get_client()
        return self._available

    def _check_available(self) -> bool:
        """Re-check Redis availability (for health checks)."""
        if self._client is None:
            return False
        try:
            self._client.ping()
            self._available = True
            return True
        except Exception:
            self._available = False
            return False

    def add(self, job_id: str, command: list[str], actor: str) -> dict[str, Any]:
        """Add a new job to Redis.

        Args:
            job_id: Unique job identifier.
            command: Command that was submitted.
            actor: Authenticated actor.

        Returns:
            The job dict.
        """
        client = self._get_client()
        if not self._available:
            # Fallback: return in-memory job (no persistence)
            logger.warning("Redis unavailable, job %s not persisted", job_id)
            return {
                "job_id": job_id,
                "command": command,
                "actor": actor,
                "status": "pending",
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "completed_at": None,
                "result": None,
                "error": None,
            }

        job = {
            "job_id": job_id,
            "command": json.dumps(command),
            "actor": actor,
            "status": "pending",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "completed_at": "",
            "result": "",
            "error": "",
        }

        key = f"{_JOB_KEY_PREFIX}{job_id}"
        pipe = client.pipeline()
        pipe.hset(key, mapping=job)
        pipe.zadd(_JOB_LIST_KEY, {job_id: time.time()})
        pipe.execute()

        # Return a dict with the original types
        return {
            "job_id": job_id,
            "command": command,
            "actor": actor,
            "status": "pending",
            "created_at": job["created_at"],
            "completed_at": None,
            "result": None,
            "error": None,
        }

    def get(self, job_id: str) -> dict[str, Any] | None:
        """Get a job by ID from Redis."""
        client = self._get_client()
        if not self._available:
            return None

        key = f"{_JOB_KEY_PREFIX}{job_id}"
        data = client.hgetall(key)
        if not data:
            return None

        return self._deserialize_job(data)

    def update(self, job_id: str, **kwargs: Any) -> dict[str, Any] | None:
        """Update a job's fields in Redis."""
        client = self._get_client()
        if not self._available:
            return None

        key = f"{_JOB_KEY_PREFIX}{job_id}"
        existing = client.hgetall(key)
        if not existing:
            return None

        # Update fields — only allowed columns
        updates = {}
        for k, v in kwargs.items():
            if k not in ALLOWED_COLUMNS:
                logger.warning("Ignoring disallowed column in Redis update: %s", k)
                continue
            if k == "command" and isinstance(v, list):
                updates[k] = json.dumps(v)
            elif v is None:
                updates[k] = ""
            else:
                updates[k] = str(v)

        if "status" in kwargs and kwargs["status"] in ("completed", "failed"):
            updates["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        client.hset(key, mapping=updates)

        # Return updated job
        data = client.hgetall(key)
        return self._deserialize_job(data)

    def list_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        """List recent jobs from Redis, newest first."""
        client = self._get_client()
        if not self._available:
            return []

        # Get most recent job IDs from sorted set
        job_ids = client.zrevrange(_JOB_LIST_KEY, 0, limit - 1)
        if not job_ids:
            return []

        # Fetch all jobs in a pipeline
        pipe = client.pipeline()
        for job_id in job_ids:
            pipe.hgetall(f"{_JOB_KEY_PREFIX}{job_id}")
        results = pipe.execute()

        jobs = []
        for data in results:
            if data:
                jobs.append(self._deserialize_job(data))

        return jobs

    def _deserialize_job(self, data: dict[str, str]) -> dict[str, Any]:
        """Deserialize a job from Redis hash to dict."""
        job = dict(data)
        # Parse JSON fields
        if "command" in job and isinstance(job["command"], str):
            try:
                job["command"] = json.loads(job["command"])
            except json.JSONDecodeError:
                pass
        # Convert empty strings to None
        for field in ("completed_at", "result", "error"):
            if job.get(field) == "":
                job[field] = None
        return job

    @property
    def redis_url(self) -> str:
        """The configured Redis URL."""
        return self._redis_url
