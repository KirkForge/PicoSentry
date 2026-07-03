from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Any, cast

logger = logging.getLogger("picodome.redis")

try:
    import redis as _redis
except ImportError:  # pragma: no cover - redis optional unless extra installed
    _redis = cast("Any", None)

# Operational errors that can occur when probing Redis for health. ImportError
# is handled separately (redis package not installed); these are the runtime
# connection failures we expect and report as in-memory fallback.
_REDIS_HEALTH_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
)
if cast("Any", _redis) is not None:
    _REDIS_HEALTH_ERRORS = (*_REDIS_HEALTH_ERRORS, _redis.RedisError)

_DEFAULT_REDIS_URL = "redis://localhost:6379/0"


@dataclass(frozen=True)
class RedisConfig:
    url: str = ""
    enabled: bool | None = None  # None = auto-detect
    socket_timeout: float = 5.0
    socket_connect_timeout: float = 3.0
    retry_on_timeout: bool = True

    @classmethod
    def from_env(cls) -> RedisConfig:
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
    config = config or RedisConfig.from_env()

    if cast("Any", _redis) is None:
        return {
            "connected": False,
            "latency_ms": 0,
            "version": "",
            "error": "redis package not installed",
            "mode": "in-memory",
            "url": "",
        }

    try:
        client = _redis.from_url(
            config.url,
            socket_timeout=config.socket_timeout,
            socket_connect_timeout=config.socket_connect_timeout,
            decode_responses=True,
        )

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

    except _REDIS_HEALTH_ERRORS as exc:
        return {
            "connected": False,
            "latency_ms": 0,
            "version": "",
            "error": str(exc),
            "mode": "in-memory",
            "url": config.url.split("@")[-1] if "@" in config.url else config.url,
        }


def is_redis_available(config: RedisConfig | None = None) -> bool:
    result = check_redis_health(config)
    return result["connected"]
