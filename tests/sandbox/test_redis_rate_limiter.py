"""Tests for Redis-backed rate limiter — B13.

Covers:
- Fallback to in-memory limiter when Redis unavailable
- Mock Redis token bucket behavior
- Rate limiting with per-actor buckets
- Status query
- Reset behavior
- Config from environment
- Tenant-prefixed actor keys
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

from picosentry.sandbox.ratelimit.limiter import RateLimitConfig
from picosentry.sandbox.ratelimit.redis_limiter import RedisTokenBucketLimiter


class TestFallbackWhenNoRedis:
    """When Redis is unavailable, falls back to in-memory limiter."""

    def test_fallback_allows_requests(self):
        limiter = RedisTokenBucketLimiter(
            config=RateLimitConfig(rate_per_second=10.0, burst_size=5),
            redis_url="redis://localhost:1/0",
        )
        # Should fall back to in-memory
        assert limiter.allow("actor-1")

    def test_fallback_enforces_limits(self):
        limiter = RedisTokenBucketLimiter(
            config=RateLimitConfig(rate_per_second=0.0, burst_size=2),
            redis_url="redis://localhost:1/0",
        )
        assert limiter.allow("actor-1")
        assert limiter.allow("actor-1")
        assert not limiter.allow("actor-1")  # exhausted

    def test_fallback_status(self):
        limiter = RedisTokenBucketLimiter(
            config=RateLimitConfig(rate_per_second=10.0, burst_size=5),
            redis_url="redis://localhost:1/0",
        )
        limiter.allow("actor-1")
        status = limiter.get_status("actor-1")
        assert status["actor"] == "actor-1"
        assert status["tokens_available"] >= 0

    def test_fallback_reset(self):
        limiter = RedisTokenBucketLimiter(
            config=RateLimitConfig(rate_per_second=0.0, burst_size=2),
            redis_url="redis://localhost:1/0",
        )
        limiter.allow("actor-1")
        limiter.allow("actor-1")
        assert not limiter.allow("actor-1")
        limiter.reset("actor-1")
        assert limiter.allow("actor-1")


class MockRedisForRateLimit:
    """In-memory mock Redis for rate limiter testing."""

    def __init__(self):
        self._data: dict[str, dict[str, float]] = {}

    def ping(self):
        return True

    def hgetall(self, key):
        return self._data.get(key, {})

    def hset(self, key, mapping=None, **kwargs):
        if key not in self._data:
            self._data[key] = {}
        if mapping:
            for k, v in mapping.items():
                self._data[key][k] = str(v)

    def expire(self, key, seconds):
        pass  # no-op for mock

    def delete(self, *keys):
        for key in keys:
            self._data.pop(key, None)

    def scan_iter(self, pattern):
        import fnmatch

        for key in list(self._data.keys()):
            if fnmatch.fnmatch(key, pattern):
                yield key

    def register_script(self, script):
        return MockLuaScript(self)

    def from_url(self, url, **kwargs):
        return self


class MockLuaScript:
    """Mock Lua script that simulates token bucket logic."""

    def __init__(self, redis_mock):
        self._redis = redis_mock

    def __call__(self, keys, args):
        key = keys[0]
        rate = float(args[0])
        burst = float(args[1])
        consume = float(args[2])
        now = float(args[3])

        data = self._redis.hgetall(key)
        tokens = float(data.get("tokens", burst))
        last_refill = float(data.get("last_refill", now))

        # Refill
        elapsed = now - last_refill
        if elapsed > 0:
            tokens = min(burst, tokens + elapsed * rate)
            last_refill = now

        # Consume
        if tokens >= consume:
            tokens -= consume
            self._redis.hset(key, mapping={"tokens": tokens, "last_refill": last_refill})
            return 1
        else:
            self._redis.hset(key, mapping={"tokens": tokens, "last_refill": last_refill})
            return 0


class TestRedisLimiterWithMock:
    """Test Redis rate limiter with mock Redis."""

    @pytest.fixture
    def limiter(self):
        limiter = RedisTokenBucketLimiter(
            config=RateLimitConfig(rate_per_second=10.0, burst_size=5),
        )
        mock_redis = MockRedisForRateLimit()
        limiter._client = mock_redis
        limiter._lua_script = mock_redis.register_script(None)
        limiter._available = True
        return limiter

    def test_allow_within_burst(self, limiter):
        assert limiter.allow("actor-1")

    def test_allow_exhausts_burst(self, limiter):
        # Burst of 5, rate=10/s
        for _ in range(5):
            assert limiter.allow("actor-1")
        # 6th should be denied (no time for refill)
        assert not limiter.allow("actor-1")

    def test_different_actors_independent(self, limiter):
        # Each actor gets their own bucket
        for _ in range(5):
            assert limiter.allow("actor-1")
        assert not limiter.allow("actor-1")
        # actor-2 still has full bucket
        assert limiter.allow("actor-2")

    def test_tenant_prefixed_actor(self, limiter):
        """Tenant-prefixed actors get separate buckets."""
        assert limiter.allow("tenant:alpha:user1")
        assert limiter.allow("tenant:beta:user1")
        # These are different actors

    def test_get_status(self, limiter):
        limiter.allow("actor-1")
        status = limiter.get_status("actor-1")
        assert status["actor"] == "actor-1"
        assert "tokens_available" in status

    def test_reset_actor(self, limiter):
        for _ in range(5):
            limiter.allow("actor-1")
        limiter.reset("actor-1")
        # Should have full bucket again
        assert limiter.allow("actor-1")


class TestRedisLimiterConfig:
    def test_default_url(self):
        limiter = RedisTokenBucketLimiter()
        assert "localhost" in limiter.redis_url

    def test_custom_url(self):
        limiter = RedisTokenBucketLimiter(redis_url="redis://myredis:6379/1")
        assert limiter.redis_url == "redis://myredis:6379/1"

    def test_url_from_env(self):
        with mock.patch.dict(os.environ, {"PICODOME_REDIS_URL": "redis://custom:6379/2"}):
            limiter = RedisTokenBucketLimiter()
            assert limiter.redis_url == "redis://custom:6379/2"
