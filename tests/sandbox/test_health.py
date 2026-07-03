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
