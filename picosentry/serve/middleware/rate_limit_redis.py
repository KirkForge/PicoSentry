"""Distributed Redis backend for the serve rate-limit middleware.

Provides a shared sliding-window counter so multiple ``picosentry serve``
replicas enforce a consistent rate limit across the whole deployment.  When
Redis is unavailable the backend falls back to the in-memory dict used by
``RateLimitMiddleware``.
"""

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger("picoshogun.ratelimit.redis")


class RedisRateLimitBackend:
    """Shared sliding-window rate-limit backend using Redis sorted sets.

    Each request is recorded as a score=timestamp member in a Redis sorted set
    keyed by ``picoshogun:ratelimit:<bucket_type>:<key>``.  Old entries are
    removed atomically with ``ZREMRANGEBYSCORE`` before counting, which gives
    a distributed equivalent of the in-memory sliding window used by
    ``RateLimitMiddleware``.

    The backend is *best-effort*: if Redis is unreachable, ``record`` and
    ``count`` return local fallback values so a single network hiccup does not
    block API traffic.
    """

    def __init__(
        self,
        redis_url: str,
        window: int = 60,
        key_prefix: str = "picoshogun:ratelimit",
    ) -> None:
        self._redis_url = redis_url
        self._window = window
        self._key_prefix = key_prefix
        self._client: Any | None = None
        self._available = False

    def _connect(self) -> Any | None:
        if self._client is not None:
            return self._client if self._available else None

        try:
            import redis as _redis  # optional dependency

            client = _redis.from_url(self._redis_url, decode_responses=True)
            client.ping()
            self._client = client
            self._available = True
            logger.info("Redis rate-limit backend connected: %s", self._redis_url)
            return client
        except ImportError:
            logger.warning("Redis package not installed; rate limit stays in-memory")
        except Exception as exc:
            logger.warning("Redis rate-limit backend connection failed: %s", exc)

        self._available = False
        return None

    def _key(self, bucket_type: str, bucket_key: str) -> str:
        return f"{self._key_prefix}:{bucket_type}:{bucket_key}"

    def record_and_count(self, bucket_type: str, bucket_key: str) -> int:
        """Record a request and return the current count in the window.

        Returns the local-only count ``-1`` when Redis is unavailable so the
        caller can fall back to its in-memory buckets.
        """
        client = self._connect()
        if client is None:
            return -1

        now = time.time()
        cutoff = now - self._window
        key = self._key(bucket_type, bucket_key)
        try:
            pipe = client.pipeline()
            pipe.zremrangebyscore(key, "-inf", cutoff)
            pipe.zadd(key, {str(now): now})
            pipe.zcard(key)
            pipe.expire(key, self._window + 1)
            _, _, count, _ = pipe.execute()
            return int(count)
        except Exception as exc:
            logger.warning("Redis rate-limit update failed: %s", exc)
            self._available = False
            self._client = None
            return -1

    def count(self, bucket_type: str, bucket_key: str) -> int:
        """Return the current count without recording a new request.

        Returns ``-1`` when Redis is unavailable so the caller can fall back.
        """
        client = self._connect()
        if client is None:
            return -1

        now = time.time()
        cutoff = now - self._window
        key = self._key(bucket_type, bucket_key)
        try:
            pipe = client.pipeline()
            pipe.zremrangebyscore(key, "-inf", cutoff)
            pipe.zcard(key)
            _, count = pipe.execute()
            return int(count)
        except Exception as exc:
            logger.warning("Redis rate-limit count failed: %s", exc)
            self._available = False
            self._client = None
            return -1

    def reset(self, bucket_type: str | None = None, bucket_key: str | None = None) -> None:
        """Clear one or all rate-limit buckets from Redis."""
        client = self._connect()
        if client is None:
            return

        try:
            if bucket_type and bucket_key:
                client.delete(self._key(bucket_type, bucket_key))
            elif bucket_type:
                for key in client.scan_iter(match=f"{self._key_prefix}:{bucket_type}:*"):
                    client.delete(key)
            else:
                for key in client.scan_iter(match=f"{self._key_prefix}:*"):
                    client.delete(key)
        except Exception as exc:
            logger.warning("Redis rate-limit reset failed: %s", exc)
            self._available = False
            self._client = None

    @property
    def available(self) -> bool:
        self._connect()
        return self._available

    @property
    def redis_url(self) -> str:
        return self._redis_url


__all__ = ["RedisRateLimitBackend"]
