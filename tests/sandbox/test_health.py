"""Tests for health check module."""

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
