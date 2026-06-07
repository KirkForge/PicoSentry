
from __future__ import annotations

import logging
import os
import time
from typing import Any

from picosentry.sandbox.ratelimit.limiter import RateLimitConfig, TokenBucketLimiter

logger = logging.getLogger("picodome.ratelimit.redis")

_DEFAULT_REDIS_URL = "redis://localhost:6379/0"


_LUA_TOKEN_BUCKET = """
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local consume = tonumber(ARGV[3])
local now = tonumber(ARGV[4])

local data = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(data[1]) or burst
local last_refill = tonumber(data[2]) or now

-- Refill
local elapsed = now - last_refill
if elapsed > 0 then
    tokens = math.min(burst, tokens + elapsed * rate)
    last_refill = now
end

-- Check and consume
if tokens >= consume then
    tokens = tokens - consume
    redis.call('HSET', key, 'tokens', tokens, 'last_refill', last_refill)
    redis.call('EXPIRE', key, 7200)
    return 1
else
    redis.call('HSET', key, 'tokens', tokens, 'last_refill', last_refill)
    redis.call('EXPIRE', key, 7200)
    return 0
end
"""


class RedisTokenBucketLimiter:

    def __init__(
        self,
        config: RateLimitConfig | None = None,
        redis_url: str | None = None,
    ) -> None:
        self._config = config or RateLimitConfig()
        self._redis_url = redis_url or os.environ.get("PICODOME_REDIS_URL", _DEFAULT_REDIS_URL)
        self._client = None
        self._lua_script = None
        self._available = False

        self._fallback = TokenBucketLimiter(config=self._config)

    def _get_client(self):
        if self._client is not None:
            return self._client

        try:
            import redis

            self._client = redis.from_url(self._redis_url, decode_responses=True)
            self._client.ping()
            self._lua_script = self._client.register_script(_LUA_TOKEN_BUCKET)
            self._available = True
            logger.info("Redis rate limiter connected: %s", self._redis_url)
        except ImportError:
            logger.warning("Redis package not installed, using in-memory rate limiter")
            self._available = False
        except Exception as exc:
            logger.warning("Redis connection failed for rate limiter: %s", exc)
            self._available = False
            self._client = None

        return self._client

    @property
    def available(self) -> bool:
        if self._client is None:
            self._get_client()
        return self._available

    def allow(self, actor: str, tokens: float = 1.0) -> bool:
        self._get_client()

        if not self._available:
            return self._fallback.allow(actor=actor, tokens=tokens)

        try:
            key = f"picodome:ratelimit:{actor}"
            now = time.time()

            lua_script = self._lua_script
            assert lua_script is not None
            result = lua_script(  # type: ignore[unreachable]
                keys=[key],
                args=[
                    str(self._config.rate_per_second),
                    str(self._config.burst_size),
                    str(tokens),
                    str(now),
                ],
            )
            return bool(result)
        except Exception as exc:
            logger.warning("Redis rate limit check failed: %s, falling back to in-memory", exc)
            self._available = False
            return self._fallback.allow(actor=actor, tokens=tokens)

    def get_status(self, actor: str) -> dict[str, Any]:
        if not self._available:
            return self._fallback.get_status(actor)

        client = self._get_client()
        try:
            key = f"picodome:ratelimit:{actor}"
            data = client.hgetall(key)
            if data:
                current_tokens = float(data.get("tokens", self._config.burst_size))
                return {
                    "actor": actor,
                    "tokens_available": round(current_tokens, 2),
                    "burst_size": self._config.burst_size,
                    "rate_per_second": self._config.rate_per_second,
                    "limited": current_tokens < 1.0,
                    "backend": "redis",
                }
        except Exception:
            pass

        return self._fallback.get_status(actor)

    def reset(self, actor: str | None = None) -> None:
        if not self._available:
            self._fallback.reset(actor)
            return

        client = self._get_client()
        try:
            if actor:
                client.delete(f"picodome:ratelimit:{actor}")
            else:

                for key in client.scan_iter("picodome:ratelimit:*"):
                    client.delete(key)
        except Exception:
            self._fallback.reset(actor)

    @property
    def config(self) -> RateLimitConfig:
        return self._config

    @property
    def redis_url(self) -> str:
        return self._redis_url
