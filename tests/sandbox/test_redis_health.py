"""Tests for Redis health check and configuration — B15.

Covers:
- RedisConfig from environment variables
- check_redis_health when Redis unavailable
- is_redis_available quick check
- Health endpoint includes Redis status
- Fallback mode when Redis not configured
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

from picosentry.sandbox.redis_health import RedisConfig, check_redis_health, is_redis_available


class TestRedisConfig:
    def test_defaults(self):
        config = RedisConfig()
        assert config.url == ""
        assert config.enabled is None  # auto-detect
        assert config.socket_timeout == 5.0
        assert config.retry_on_timeout is True

    def test_from_env_with_url(self):
        with mock.patch.dict(os.environ, {"PICODOME_REDIS_URL": "redis://myhost:6379/2"}):
            config = RedisConfig.from_env()
            assert config.url == "redis://myhost:6379/2"

    def test_from_env_enabled(self):
        with mock.patch.dict(
            os.environ,
            {
                "PICODOME_REDIS_URL": "redis://localhost:6379/0",
                "PICODOME_REDIS_ENABLED": "true",
            },
        ):
            config = RedisConfig.from_env()
            assert config.enabled is True

    def test_from_env_disabled(self):
        with mock.patch.dict(
            os.environ,
            {
                "PICODOME_REDIS_URL": "redis://localhost:6379/0",
                "PICODOME_REDIS_ENABLED": "false",
            },
        ):
            config = RedisConfig.from_env()
            assert config.enabled is False

    def test_from_env_timeout(self):
        with mock.patch.dict(
            os.environ,
            {
                "PICODOME_REDIS_URL": "redis://localhost:6379/0",
                "PICODOME_REDIS_TIMEOUT": "10.0",
            },
        ):
            config = RedisConfig.from_env()
            assert config.socket_timeout == 10.0

    def test_from_env_defaults(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            config = RedisConfig.from_env()
            assert config.url == "redis://localhost:6379/0"
            assert config.enabled is None

    def test_frozen(self):
        config = RedisConfig()
        with pytest.raises(AttributeError):
            config.url = "changed"  # type: ignore


class TestRedisHealthCheck:
    def test_unavailable_returns_in_memory_mode(self):
        """When Redis is not running, returns in-memory mode."""
        config = RedisConfig(url="redis://localhost:1/0")
        result = check_redis_health(config)
        assert result["connected"] is False
        assert result["mode"] == "in-memory"
        assert result["error"]  # has an error message

    def test_result_has_expected_keys(self):
        config = RedisConfig(url="redis://localhost:1/0")
        result = check_redis_health(config)
        assert "connected" in result
        assert "latency_ms" in result
        assert "version" in result
        assert "error" in result
        assert "mode" in result

    def test_url_redacted(self):
        """URL with auth should be redacted in health output."""
        config = RedisConfig(url="redis://user:password@myhost:6379/0")
        result = check_redis_health(config)
        # The URL in result should not contain the password
        assert "password" not in result.get("url", "")


class TestIsRedisAvailable:
    def test_not_available_when_no_redis(self):
        config = RedisConfig(url="redis://localhost:1/0")
        assert is_redis_available(config) is False

    def test_available_uses_default_config(self):
        """Default config tries localhost — likely not running in CI."""
        # Just ensure it doesn't crash
        result = is_redis_available()
        assert isinstance(result, bool)


class TestHealthEndpointIntegration:
    def test_health_includes_redis_status(self):
        """Verify the /health endpoint structure includes redis key."""
        # This tests the response format, not a live server
        from picosentry.sandbox.redis_health import check_redis_health

        redis_health = check_redis_health()
        expected_keys = {"connected", "latency_ms", "version", "error", "mode"}
        assert expected_keys.issubset(set(redis_health.keys()))
