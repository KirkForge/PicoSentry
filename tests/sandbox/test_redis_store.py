"""Tests for Redis-backed scan job store — B12.

Covers:
- Redis unavailable fallback (no Redis running in CI)
- Job creation, retrieval, update, list with mock Redis
- Serialization/deserialization of job data
- Health check (available property)
- Config from PICODOME_REDIS_URL env var
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

from picosentry.sandbox.daemon.redis_store import (
    _DEFAULT_REDIS_URL,
    RedisScanJobStore,
)


class TestRedisStoreFallback:
    """Test behavior when Redis is unavailable."""

    def test_unavailable_when_no_redis(self):
        """Redis not running → store reports unavailable."""
        store = RedisScanJobStore(redis_url="redis://localhost:1/0")
        # This will try to connect and fail
        assert not store.available

    def test_add_raises_when_unavailable(self):
        """WO5.0.0-017: add() with Redis down must be loud — the old
        success-shaped return made callers 201-accept a job that 404s."""
        from picosentry.sandbox.daemon.redis_store import RedisStoreUnavailable

        store = RedisScanJobStore(redis_url="redis://localhost:1/0")
        with pytest.raises(RedisStoreUnavailable):
            store.add("job-1", ["ls"], "alice")

    def test_get_raises_when_unavailable(self):
        """WO6.0.0-018: get() with Redis down must be loud — the old None
        return masqueraded as "no such job" (404) during an outage."""
        from picosentry.sandbox.daemon.redis_store import RedisStoreUnavailable

        store = RedisScanJobStore(redis_url="redis://localhost:1/0")
        with pytest.raises(RedisStoreUnavailable):
            store.get("job-1")

    def test_update_raises_when_unavailable(self):
        """WO6.0.0-018: update() with Redis down must be loud — the old None
        return masqueraded as "no such job" during an outage."""
        from picosentry.sandbox.daemon.redis_store import RedisStoreUnavailable

        store = RedisScanJobStore(redis_url="redis://localhost:1/0")
        with pytest.raises(RedisStoreUnavailable):
            store.update("job-1", status="completed")

    def test_list_raises_when_unavailable(self):
        """WO6.0.0-018: list_recent() with Redis down must be loud — the old
        [] return masqueraded as "count: 0" during an outage."""
        from picosentry.sandbox.daemon.redis_store import RedisStoreUnavailable

        store = RedisScanJobStore(redis_url="redis://localhost:1/0")
        with pytest.raises(RedisStoreUnavailable):
            store.list_recent()


class MockRedis:
    """In-memory mock Redis for testing without a real Redis server."""

    def __init__(self, **kwargs):
        self._data: dict[str, dict[str, str]] = {}
        self._sorted_sets: dict[str, dict[str, float]] = {}
        self.expires: list[tuple[str, int]] = []

    def ping(self):
        return True

    def hset(self, key, mapping=None, **kwargs):
        if key not in self._data:
            self._data[key] = {}
        if mapping:
            self._data[key].update(mapping)

    def hgetall(self, key):
        return self._data.get(key, {})

    def zadd(self, key, mapping=None, **kwargs):
        if key not in self._sorted_sets:
            self._sorted_sets[key] = {}
        if mapping:
            self._sorted_sets[key].update(mapping)

    def zrevrange(self, key, start, stop):
        if key not in self._sorted_sets:
            return []
        sorted_items = sorted(
            self._sorted_sets[key].items(),
            key=lambda x: x[1],
            reverse=True,
        )
        if stop == -1:
            return [item[0] for item in sorted_items[start:]]
        return [item[0] for item in sorted_items[start : stop + 1]]

    def from_url(self, url, **kwargs):
        return self

    class Pipeline:
        def __init__(self, redis_mock):
            self._redis = redis_mock
            self._commands = []

        def hset(self, key, mapping=None, **kwargs):
            self._commands.append(("hset", key, mapping))

        def zadd(self, key, mapping=None, **kwargs):
            self._commands.append(("zadd", key, mapping))

        def expire(self, key, ttl):
            self._commands.append(("expire", key, ttl))

        def hgetall(self, key):
            self._commands.append(("hgetall", key))

        def execute(self):
            results = []
            for cmd in self._commands:
                if cmd[0] == "hset":
                    self._redis.hset(cmd[1], mapping=cmd[2])
                    results.append(True)
                elif cmd[0] == "zadd":
                    self._redis.zadd(cmd[1], mapping=cmd[2])
                    results.append(True)
                elif cmd[0] == "expire":
                    self._redis.expires.append((cmd[1], cmd[2]))
                    results.append(True)
                elif cmd[0] == "hgetall":
                    results.append(self._redis.hgetall(cmd[1]))
            return results

        def __getattr__(self, name):
            # Forward any other method calls
            def method(*args, **kwargs):
                self._commands.append((name, args, kwargs))
                return self

            return method

    def pipeline(self):
        return self.Pipeline(self)


class TestRedisStoreWithMock:
    """Test Redis store with a mock Redis client."""

    @pytest.fixture
    def store(self):
        """Create a Redis store with mock client."""
        s = RedisScanJobStore()
        mock_redis = MockRedis()
        s._client = mock_redis
        s._available = True
        return s

    def test_add_job(self, store):
        job = store.add("job-1", ["ls", "-la"], "alice")
        assert job["job_id"] == "job-1"
        assert job["command"] == ["ls", "-la"]
        assert job["actor"] == "alice"
        assert job["status"] == "pending"

    def test_get_job(self, store):
        store.add("job-1", ["ls"], "alice")
        job = store.get("job-1")
        assert job is not None
        assert job["job_id"] == "job-1"
        assert job["command"] == ["ls"]

    def test_get_nonexistent(self, store):
        assert store.get("no-such-job") is None

    def test_update_job(self, store):
        store.add("job-1", ["ls"], "alice")
        result = store.update("job-1", status="completed")
        assert result is not None
        assert result["status"] == "completed"
        assert result["completed_at"] is not None

    def test_update_nonexistent(self, store):
        assert store.update("no-such-job", status="completed") is None

    def test_list_recent(self, store):
        store.add("job-1", ["ls"], "alice")
        store.add("job-2", ["cat"], "bob")
        jobs = store.list_recent()
        assert len(jobs) == 2

    def test_list_recent_limit(self, store):
        for i in range(10):
            store.add(f"job-{i}", ["cmd"], "user")
        jobs = store.list_recent(limit=3)
        assert len(jobs) == 3

    def test_deserialize_command_json(self, store):
        """Verify command list is serialized/deserialized correctly."""
        store.add("job-1", ["ls", "-la", "/tmp"], "alice")
        job = store.get("job-1")
        assert job["command"] == ["ls", "-la", "/tmp"]

    def test_add_sets_hash_ttl(self, store):
        """WO5.0.0-017: the promised per-job EXPIRE never existed — job hashes
        grew without bound."""
        from picosentry.sandbox.daemon.redis_store import _DEFAULT_JOB_TTL_SECONDS, _JOB_KEY_PREFIX

        store.add("job-ttl", ["ls"], "alice")
        assert store._client.expires == [(_JOB_KEY_PREFIX + "job-ttl", _DEFAULT_JOB_TTL_SECONDS)]

    def test_add_ttl_disabled_via_env(self, store, monkeypatch):
        monkeypatch.setenv("PICODOME_REDIS_JOB_TTL", "0")
        store.add("job-nottl", ["ls"], "alice")
        assert store._client.expires == []

    def test_empty_fields_become_none(self, store):
        """Verify empty strings become None for completed_at, result, error."""
        job = store.add("job-1", ["ls"], "alice")
        assert job["completed_at"] is None
        assert job["result"] is None
        assert job["error"] is None


class TestRedisStoreConfig:
    def test_default_url(self):
        store = RedisScanJobStore()
        assert store.redis_url == _DEFAULT_REDIS_URL

    def test_custom_url(self):
        store = RedisScanJobStore(redis_url="redis://myredis:6379/1")
        assert store.redis_url == "redis://myredis:6379/1"

    def test_url_from_env(self):
        with mock.patch.dict(os.environ, {"PICODOME_REDIS_URL": "redis://custom:6379/2"}):
            store = RedisScanJobStore()
            assert store.redis_url == "redis://custom:6379/2"


class TestRedisStoreExceptionNarrowing:
    """Redis client probe must tolerate expected failures and propagate bugs."""

    def test_expected_connection_error_marks_unavailable(self, caplog, monkeypatch):
        import logging
        from picosentry.sandbox.daemon import redis_store

        store = RedisScanJobStore(redis_url="redis://localhost:1/0")

        if redis_store._redis is None:

            class _FakeRedis:
                @staticmethod
                def from_url(_url, **_kwargs):
                    raise OSError("connection refused")

            monkeypatch.setattr(redis_store, "_redis", _FakeRedis())
        else:

            def _boom(*_args, **_kwargs):
                raise redis_store._redis.ConnectionError("connection refused")

            monkeypatch.setattr(redis_store._redis, "from_url", _boom)

        picodome_logger = logging.getLogger("picodome")
        saved_propagate = picodome_logger.propagate
        picodome_logger.propagate = True
        try:
            with caplog.at_level(logging.WARNING, logger="picodome.daemon.redis_store"):
                assert not store.available

            assert not store._available
            assert any("Redis connection failed" in r.message for r in caplog.records)
        finally:
            picodome_logger.propagate = saved_propagate

    def test_unexpected_error_propagates(self, monkeypatch):
        from picosentry.sandbox.daemon import redis_store

        store = RedisScanJobStore(redis_url="redis://localhost:1/0")

        class _FakeRedis:
            @staticmethod
            def from_url(_url, **_kwargs):
                raise NameError("programmer mistake")

        monkeypatch.setattr(redis_store, "_redis", _FakeRedis())

        with pytest.raises(NameError, match="programmer mistake"):
            store._get_client()


class TestRedisStoreLiveness:
    """A cached client whose ping fails (Redis restart) must reset and reconnect."""

    def test_cached_client_reset_on_lost_connection(self, monkeypatch):
        from picosentry.sandbox.daemon import redis_store
        from picosentry.sandbox.daemon.redis_store import RedisStoreUnavailable

        store = RedisScanJobStore()
        mock_redis = MockRedis()
        store._client = mock_redis
        store._available = True

        def _dead(*_a, **_kw):
            raise OSError("connection reset")

        mock_redis.ping = _dead

        if redis_store._redis is not None:

            def _no_reconnect(*_a, **_kw):
                raise OSError("reconnect refused")

            monkeypatch.setattr(redis_store._redis, "from_url", _no_reconnect)

        # WO6.0.0-018: a lost connection used to masquerade as None (404) —
        # now it raises RedisStoreUnavailable so the HTTP layer can 503.
        with pytest.raises(RedisStoreUnavailable):
            store.get("job-1")
        assert store._available is False
        assert store._client is None
