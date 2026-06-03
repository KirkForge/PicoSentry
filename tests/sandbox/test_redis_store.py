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

    def test_add_returns_job_when_unavailable(self):
        """Add still returns a job dict even when Redis is down."""
        store = RedisScanJobStore(redis_url="redis://localhost:1/0")
        job = store.add("job-1", ["ls"], "alice")
        assert job["job_id"] == "job-1"
        assert job["status"] == "pending"
        assert job["command"] == ["ls"]

    def test_get_returns_none_when_unavailable(self):
        store = RedisScanJobStore(redis_url="redis://localhost:1/0")
        assert store.get("job-1") is None

    def test_update_returns_none_when_unavailable(self):
        store = RedisScanJobStore(redis_url="redis://localhost:1/0")
        assert store.update("job-1", status="completed") is None

    def test_list_returns_empty_when_unavailable(self):
        store = RedisScanJobStore(redis_url="redis://localhost:1/0")
        assert store.list_recent() == []


class MockRedis:
    """In-memory mock Redis for testing without a real Redis server."""

    def __init__(self, **kwargs):
        self._data: dict[str, dict[str, str]] = {}
        self._sorted_sets: dict[str, dict[str, float]] = {}

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
