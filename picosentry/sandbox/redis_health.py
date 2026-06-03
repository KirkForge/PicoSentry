"""Redis health check and configuration for horizontal scaling.

Provides a unified health check for Redis connectivity and
a configuration helper for setting up Redis-backed stores.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("picodome.redis")

_DEFAULT_REDIS_URL = "redis://localhost:6379/0"


@dataclass(frozen=True)
class RedisConfig:
    """Redis configuration for all Redis-backed stores.

    Attributes:
        url: Redis connection URL.
        enabled: Whether Redis is enabled (auto-detected if not set).
        socket_timeout: Socket timeout in seconds.
        socket_connect_timeout: Connection timeout in seconds.
        retry_on_timeout: Whether to retry on timeout.
    """

    url: str = ""
    enabled: bool | None = None  # None = auto-detect
    socket_timeout: float = 5.0
    socket_connect_timeout: float = 3.0
    retry_on_timeout: bool = True

    @classmethod
    def from_env(cls) -> RedisConfig:
        """Create RedisConfig from environment variables.

        Env vars:
          PICODOME_REDIS_URL — Redis URL (required for Redis mode)
          PICODOME_REDIS_ENABLED — 'true' or 'false' (optional, auto-detect if unset)
          PICODOME_REDIS_TIMEOUT — socket timeout in seconds (optional)
        """
        url = os.environ.get("PICODOME_REDIS_URL", "")
        enabled_str = os.environ.get("PICODOME_REDIS_ENABLED", "")
        timeout_str = os.environ.get("PICODOME_REDIS_TIMEOUT", "")

        enabled = None
        if enabled_str:
            enabled = enabled_str.lower() in ("true", "1", "yes")

        timeout = float(timeout_str) if timeout_str else 5.0

        return cls(
            url=url or _DEFAULT_REDIS_URL,
            enabled=enabled,
            socket_timeout=timeout,
        )


def check_redis_health(config: RedisConfig | None = None) -> dict[str, Any]:
    """Check Redis connectivity and return health status.

    Returns:
        Dict with keys:
          - connected: bool
          - latency_ms: float (0 if not connected)
          - version: str (empty if not connected)
          - error: str (empty if connected)
          - mode: "redis" or "in-memory"
    """
    config = config or RedisConfig.from_env()

    try:
        import redis

        client = redis.from_url(
            config.url,
            socket_timeout=config.socket_timeout,
            socket_connect_timeout=config.socket_connect_timeout,
            decode_responses=True,
        )

        # Measure latency
        import time

        start = time.monotonic()
        client.ping()
        latency = (time.monotonic() - start) * 1000  # ms

        info = client.info("server")
        version = info.get("redis_version", "unknown")

        client.close()

        return {
            "connected": True,
            "latency_ms": round(latency, 2),
            "version": version,
            "error": "",
            "mode": "redis",
            "url": config.url.split("@")[-1] if "@" in config.url else config.url,
        }

    except ImportError:
        return {
            "connected": False,
            "latency_ms": 0,
            "version": "",
            "error": "redis package not installed",
            "mode": "in-memory",
            "url": "",
        }
    except Exception as exc:
        return {
            "connected": False,
            "latency_ms": 0,
            "version": "",
            "error": str(exc),
            "mode": "in-memory",
            "url": config.url.split("@")[-1] if "@" in config.url else config.url,
        }


def is_redis_available(config: RedisConfig | None = None) -> bool:
    """Quick check if Redis is available for use."""
    result = check_redis_health(config)
    return result["connected"]
