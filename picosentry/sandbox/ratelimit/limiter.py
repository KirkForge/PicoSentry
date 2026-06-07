
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("picodome.ratelimit")


@dataclass(frozen=True)
class RateLimitConfig:


    rate_per_second: float = 2.0

    burst_size: int = 10

    max_actors: int = 10000

    idle_timeout_seconds: int = 3600

    global_rps: float = 25.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "burst_size": self.burst_size,
            "global_rps": self.global_rps,
            "idle_timeout_seconds": self.idle_timeout_seconds,
            "max_actors": self.max_actors,
            "rate_per_second": self.rate_per_second,
        }


class _TokenBucket:

    __slots__ = ("burst", "last_refill", "rate", "tokens")

    def __init__(self, rate: float, burst: int) -> None:
        self.tokens: float = float(burst)
        self.last_refill: float = time.monotonic()
        self.rate = rate
        self.burst = burst

    def refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_refill = now

    def consume(self, tokens: float = 1.0) -> bool:
        self.refill()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


class TokenBucketLimiter:

    def __init__(self, config: RateLimitConfig | None = None) -> None:
        self._config = config or RateLimitConfig()
        self._buckets: dict[str, _TokenBucket] = {}
        self._global_bucket: _TokenBucket | None = None
        self._lock = threading.Lock()
        self._last_cleanup = time.monotonic()

        if self._config.global_rps > 0:
            self._global_bucket = _TokenBucket(
                rate=self._config.global_rps,
                burst=int(self._config.global_rps * 10),
            )

    def allow(self, actor: str, tokens: float = 1.0) -> bool:
        with self._lock:

            if self._global_bucket and not self._global_bucket.consume(tokens):
                logger.debug("Global rate limit hit: actor=%s", actor)
                return False


            if actor not in self._buckets:

                if len(self._buckets) >= self._config.max_actors:
                    self._cleanup_stale()

                self._buckets[actor] = _TokenBucket(
                    rate=self._config.rate_per_second,
                    burst=self._config.burst_size,
                )

            allowed = self._buckets[actor].consume(tokens)
            if not allowed:
                logger.debug("Rate limit hit for actor=%s", actor)


            now = time.monotonic()
            if now - self._last_cleanup > 60:
                self._cleanup_stale()
                self._last_cleanup = now

            return allowed

    def get_status(self, actor: str) -> dict[str, Any]:
        with self._lock:
            if actor in self._buckets:
                bucket = self._buckets[actor]
                bucket.refill()
                return {
                    "actor": actor,
                    "tokens_available": round(bucket.tokens, 2),
                    "burst_size": bucket.burst,
                    "rate_per_second": bucket.rate,
                    "limited": bucket.tokens < 1.0,
                }
            return {
                "actor": actor,
                "tokens_available": self._config.burst_size,
                "burst_size": self._config.burst_size,
                "rate_per_second": self._config.rate_per_second,
                "limited": False,
            }

    def reset(self, actor: str | None = None) -> None:
        with self._lock:
            if actor:
                self._buckets.pop(actor, None)
            else:
                self._buckets.clear()

    @property
    def config(self) -> RateLimitConfig:
        return self._config

    def _cleanup_stale(self) -> None:
        now = time.monotonic()
        cutoff = now - self._config.idle_timeout_seconds
        stale = [actor for actor, bucket in self._buckets.items() if bucket.last_refill < cutoff]
        for actor in stale:
            del self._buckets[actor]
        if stale:
            logger.debug("Cleaned up %d stale rate limit buckets", len(stale))
