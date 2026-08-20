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
_DEFAULT_JOB_TTL_SECONDS = 7 * 24 * 3600


def _job_ttl_seconds() -> int:
    try:
        return int(os.environ.get("PICODOME_REDIS_JOB_TTL", _DEFAULT_JOB_TTL_SECONDS))
    except ValueError:
        return _DEFAULT_JOB_TTL_SECONDS


class RedisStoreUnavailable(RuntimeError):
    """Redis is down/unconfigured — the job could NOT be persisted."""


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
            try:
                self._client.ping()
            except _REDIS_CLIENT_ERRORS:
                logger.warning("Redis connection lost; will attempt reconnect")
                self._client = None
                self._available = False

        if self._client is not None:
            return self._client

        if _redis is None:
            logger.warning("Redis package not installed, RedisScanJobStore unavailable")
            self._available = False
            return None

        try:
            self._client = _redis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=2.0,
                socket_timeout=2.0,
            )

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
        self._get_client()
        return self._available

    def add(self, job_id: str, command: list[str], actor: str) -> dict[str, Any]:
        client = self._get_client()
        if not self._available or client is None:
            # WO5.0.0-017: this used to return a success-shaped pending dict,
            # so callers 201-accepted a job that later 404'd — a fake success.
            logger.error("Redis unavailable, job %s NOT persisted — rejecting", job_id)
            raise RedisStoreUnavailable(f"Redis unavailable, job {job_id} not persisted")

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
        ttl = _job_ttl_seconds()
        if ttl > 0:
            # WO5.0.0-017: the promised hash TTL never existed — job hashes
            # grew without bound. 0/negative disables (keep forever).
            pipe.expire(key, ttl)
        # Prune (WO4.0.0-019): _max_jobs was dead — the recent-jobs zset grew
        # forever. Trim oldest beyond the cap; their hash keys expire via TTL.
        pipe.zremrangebyrank(_JOB_LIST_KEY, 0, -(self._max_jobs + 1))
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
            # WO6.0.0-018: reads used to return None when Redis was down,
            # so a /api/v1/scan/<id> GET during an outage 404'd "no such job"
            # — indistinguishable from a real not-found. Raise so the HTTP
            # layer can surface a 503 (writes already 503'd via WO5-017).
            raise RedisStoreUnavailable(f"Redis unavailable, get {job_id} cannot be served")

        key = f"{_JOB_KEY_PREFIX}{job_id}"
        data = client.hgetall(key)
        if not data:
            return None

        return self._deserialize_job(data)

    def update(self, job_id: str, **kwargs: Any) -> dict[str, Any] | None:
        client = self._get_client()
        if not self._available:
            # WO6.0.0-018: raise like get() — None masqueraded as "no such job".
            raise RedisStoreUnavailable(f"Redis unavailable, update {job_id} cannot be served")

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
            elif isinstance(v, (dict, list)):
                updates[k] = json.dumps(v, default=str)
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
            # WO6.0.0-018: raise like get()/update() — [] masqueraded as "no
            # jobs" during an outage.
            raise RedisStoreUnavailable("Redis unavailable, list_recent cannot be served")

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

        if "result" in job and isinstance(job["result"], str):
            with contextlib.suppress(json.JSONDecodeError):
                job["result"] = json.loads(job["result"])

        for field in ("completed_at", "result", "error"):
            if job.get(field) == "":
                job[field] = None
        return job

    @property
    def redis_url(self) -> str:
        return self._redis_url
