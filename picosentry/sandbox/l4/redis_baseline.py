"""Redis-backed baseline store — horizontal scale shared state.

Stores L4 behavioral baselines in Redis so all replicas share
the same baseline data. Falls back to shipped baselines when
Redis is unavailable.

Configuration:
  PICODOME_REDIS_URL — Redis connection URL (default: redis://localhost:6379/0)
"""

from __future__ import annotations

import json
import logging
import os

from picosentry.sandbox.l4.baseline import SHIPPED_BASELINES
from picosentry.sandbox.l4.models import Baseline

logger = logging.getLogger("picodome.l4.redis_baseline")

_DEFAULT_REDIS_URL = "redis://localhost:6379/0"
_BASELINE_KEY_PREFIX = "picodome:baseline:"


class RedisBaselineStore:
    """Redis-backed baseline store for horizontal scaling.

    Stores custom baselines in Redis, falls back to shipped baselines
    when Redis is unavailable.

    Args:
        redis_url: Redis connection URL.
    """

    def __init__(self, redis_url: str | None = None) -> None:
        self._redis_url = redis_url or os.environ.get("PICODOME_REDIS_URL", _DEFAULT_REDIS_URL)
        self._client = None
        self._available = False

    def _get_client(self):
        """Lazy-init Redis client."""
        if self._client is not None:
            return self._client

        try:
            import redis

            self._client = redis.from_url(self._redis_url, decode_responses=True)
            self._client.ping()
            self._available = True
            logger.info("Redis baseline store connected: %s", self._redis_url)
        except ImportError:
            logger.warning("Redis package not installed, baseline store unavailable")
            self._available = False
        except Exception as exc:
            logger.warning("Redis connection failed for baseline store: %s", exc)
            self._available = False
            self._client = None

        return self._client

    @property
    def available(self) -> bool:
        """Check if Redis is available."""
        if self._client is None:
            self._get_client()
        return self._available

    def get(self, name: str) -> Baseline | None:
        """Get a baseline by name.

        Checks Redis first, falls back to shipped baselines.

        Args:
            name: Baseline name.

        Returns:
            Baseline object, or None if not found.
        """
        # Try Redis first
        if self._available:
            client = self._get_client()
            try:
                key = f"{_BASELINE_KEY_PREFIX}{name}"
                data = client.get(key)
                if data:
                    return self._deserialize(data)
            except Exception as exc:
                logger.warning("Redis baseline get failed: %s", exc)

        # Fall back to shipped baselines
        if name in SHIPPED_BASELINES:
            return SHIPPED_BASELINES[name]

        return None

    def set(self, baseline: Baseline) -> None:
        """Store a custom baseline in Redis.

        Args:
            baseline: The Baseline to store.
        """
        if not self._available:
            logger.warning("Redis unavailable, cannot store baseline '%s'", baseline.name)
            return

        client = self._get_client()
        try:
            key = f"{_BASELINE_KEY_PREFIX}{baseline.name}"
            client.set(key, self._serialize(baseline))
            logger.info("Stored baseline '%s' in Redis", baseline.name)
        except Exception as exc:
            logger.warning("Redis baseline set failed: %s", exc)

    def delete(self, name: str) -> bool:
        """Delete a custom baseline from Redis.

        Returns:
            True if deleted, False if not found or unavailable.
        """
        if not self._available:
            return False

        client = self._get_client()
        try:
            key = f"{_BASELINE_KEY_PREFIX}{name}"
            result = client.delete(key)
            return bool(result)
        except Exception as exc:
            logger.warning("Redis baseline delete failed: %s", exc)
            return False

    def list_custom(self) -> list[str]:
        """List custom baseline names stored in Redis."""
        if not self._available:
            return []

        client = self._get_client()
        try:
            keys = list(client.scan_iter(f"{_BASELINE_KEY_PREFIX}*"))
            return [k.replace(_BASELINE_KEY_PREFIX, "") for k in keys]
        except Exception:
            return []

    def list_all(self) -> list[str]:
        """List all baseline names (shipped + custom)."""
        shipped = list(SHIPPED_BASELINES.keys())
        custom = self.list_custom()
        # Merge without duplicates
        seen = set(shipped)
        for name in custom:
            if name not in seen:
                shipped.append(name)
                seen.add(name)
        return shipped

    def _serialize(self, baseline: Baseline) -> str:
        """Serialize a Baseline to JSON string."""
        data = {
            "name": baseline.name,
            "package": baseline.package,
            "version": baseline.version,
            "expected_network_calls": baseline.expected_network_calls,
            "expected_dns_queries": baseline.expected_dns_queries,
            "expected_fs_ops": baseline.expected_fs_ops,
            "expected_spawns": baseline.expected_spawns,
            "expected_runtime_ms_range": list(baseline.expected_runtime_ms_range),
            "allowed_domains": baseline.allowed_domains,
            "allowed_paths": baseline.allowed_paths,
            "notes": baseline.notes,
        }
        return json.dumps(data, sort_keys=True)

    def _deserialize(self, data: str) -> Baseline:
        """Deserialize a Baseline from JSON string."""
        d = json.loads(data)
        runtime_range = tuple(d.get("expected_runtime_ms_range", (0, 0)))
        return Baseline(
            name=d["name"],
            package=d.get("package", ""),
            version=d.get("version", "*"),
            expected_network_calls=d.get("expected_network_calls", 0),
            expected_dns_queries=d.get("expected_dns_queries", 0),
            expected_fs_ops=d.get("expected_fs_ops", 0),
            expected_spawns=d.get("expected_spawns", 0),
            expected_runtime_ms_range=runtime_range,
            allowed_domains=d.get("allowed_domains", []),
            allowed_paths=d.get("allowed_paths", []),
            notes=d.get("notes", ""),
        )

    @property
    def redis_url(self) -> str:
        return self._redis_url
