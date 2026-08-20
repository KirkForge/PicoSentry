"""Tests for health check module."""

import pytest

from picosentry.sandbox.health import check_health, check_readiness


class TestHealthCheck:
    def test_check_health_returns_list(self):
        results = check_health()
        assert isinstance(results, list)
        assert len(results) > 0

    def test_version_check_healthy(self):
        results = check_health()
        version_check = next(r for r in results if r.component == "version")
        assert version_check.healthy is True

    def test_backend_check_exists(self):
        results = check_health()
        components = [r.component for r in results]
        assert "sandbox_backend" in components

    def test_check_readiness(self):
        result = check_readiness()
        assert result.component == "readiness"
        assert isinstance(result.healthy, bool)


class TestHealthExceptionNarrowing:
    """Unexpected programmer errors in health probes must propagate."""

    def test_backend_probe_unexpected_error_propagates(self, monkeypatch):
        def _boom():
            raise NameError("programmer bug")

        monkeypatch.setattr("picosentry.sandbox.health.get_backend", _boom)
        with pytest.raises(NameError, match="programmer bug"):
            check_health()

    def test_readiness_unexpected_error_propagates(self, monkeypatch):
        def _boom():
            raise NameError("programmer bug")

        monkeypatch.setattr("picosentry.sandbox.health.get_backend", _boom)
        with pytest.raises(NameError, match="programmer bug"):
            check_readiness()

    def test_backend_probe_expected_error_returns_unhealthy(self, monkeypatch):
        def _boom():
            raise RuntimeError("backend unavailable")

        monkeypatch.setattr("picosentry.sandbox.health.get_backend", _boom)
        results = {r.component: r for r in check_health()}
        assert results["sandbox_backend"].healthy is False
        assert "backend unavailable" in results["sandbox_backend"].detail


class TestRedisHealthBranch:
    """WO6.0.0-018: health used to report "backend=jsonl healthy=True" for
    PICODOME_STORE_BACKEND=redis even when Redis was down — the sqlite-only
    special-casing missed the redis branch entirely."""

    def test_redis_backend_reported_truthfully_when_down(self, monkeypatch):
        # Force the redis store to report unavailable (no real Redis needed).
        class _DownStore:
            available = False

        monkeypatch.setenv("PICODOME_STORE_BACKEND", "redis")
        monkeypatch.setattr("picosentry.sandbox.daemon.redis_store.RedisScanJobStore", lambda: _DownStore())
        results = {r.component: r for r in check_health()}
        assert "store_backend" in results
        assert results["store_backend"].healthy is False
        assert "backend=redis" in results["store_backend"].detail
        assert "connected=False" in results["store_backend"].detail

    def test_redis_backend_reported_healthy_when_up(self, monkeypatch):
        class _UpStore:
            available = True

        monkeypatch.setenv("PICODOME_STORE_BACKEND", "redis")
        monkeypatch.setattr("picosentry.sandbox.daemon.redis_store.RedisScanJobStore", lambda: _UpStore())
        results = {r.component: r for r in check_health()}
        assert results["store_backend"].healthy is True
        assert "connected=True" in results["store_backend"].detail
