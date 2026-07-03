from __future__ import annotations

import contextlib
import json
import logging
import os
import time
from typing import Any, cast

logger = logging.getLogger("picodome.daemon.redis_store")

try:
    import redis as _redis
except ImportError:  # pragma: no cover - redis optional unless extra installed
    _redis = cast("Any", None)

# Operational errors that can occur when probing/lazily-connecting to Redis.
# ImportError is handled separately (redis package not installed); these are
# the runtime connection failures we expect and tolerate by marking the store
# unavailable.
_REDIS_CLIENT_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
)
if _redis is not None:
    _REDIS_CLIENT_ERRORS = (*_REDIS_CLIENT_ERRORS, _redis.RedisError)

_DEFAULT_REDIS_URL = "redis://localhost:6379/0"
_JOB_KEY_PREFIX = "picodome:job:"
_JOB_LIST_KEY = "picodome:jobs:recent"


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
    def __init__(
        self,
        redis_url: str | None = None,
        max_jobs: int = 1000,
    ) -> None:
        self._redis_url = redis_url or os.environ.get("PICODOME_REDIS_URL", _DEFAULT_REDIS_URL)
        self._max_jobs = max_jobs
        self._client: Any = None
        self._available = False

    def _get_client(self):
        if self._client is not None:
            return self._client

        if _redis is None:
            logger.warning("Redis package not installed, RedisScanJobStore unavailable")
            self._available = False
            return None

        try:
            self._client = _redis.from_url(self._redis_url, decode_responses=True)

            self._client.ping()
            self._available = True
            logger.info("Redis connected: %s", self._redis_url)
        except _REDIS_CLIENT_ERRORS as exc:
            logger.warning("Redis connection failed: %s", exc)
            self._available = False
            self._client = None

        return self._client

    @property
    def available(self) -> bool:
        if self._client is None:
            self._get_client()
        return self._available

    def add(self, job_id: str, command: list[str], actor: str) -> dict[str, Any]:
        client = self._get_client()
        if not self._available:
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
        client = self._get_client()
        if not self._available:
            return None

        key = f"{_JOB_KEY_PREFIX}{job_id}"
        data = client.hgetall(key)
        if not data:
            return None

        return self._deserialize_job(data)

    def update(self, job_id: str, **kwargs: Any) -> dict[str, Any] | None:
        client = self._get_client()
        if not self._available:
            return None

        key = f"{_JOB_KEY_PREFIX}{job_id}"
        existing = client.hgetall(key)
        if not existing:
            return None

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

        data = client.hgetall(key)
        return self._deserialize_job(data)

    def list_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        client = self._get_client()
        if not self._available:
            return []

        job_ids = client.zrevrange(_JOB_LIST_KEY, 0, limit - 1)
        if not job_ids:
            return []

        pipe = client.pipeline()
        for job_id in job_ids:
            pipe.hgetall(f"{_JOB_KEY_PREFIX}{job_id}")
        results = pipe.execute()

        return [self._deserialize_job(data) for data in results if data]

    def _deserialize_job(self, data: dict[str, str]) -> dict[str, Any]:
        job: dict[str, Any] = dict(data)

        if "command" in job and isinstance(job["command"], str):
            with contextlib.suppress(json.JSONDecodeError):
                job["command"] = json.loads(job["command"])

        for field in ("completed_at", "result", "error"):
            if job.get(field) == "":
                job[field] = None
        return job

    @property
    def redis_url(self) -> str:
        return self._redis_url
