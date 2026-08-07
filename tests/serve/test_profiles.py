from __future__ import annotations

import logging
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from picosentry.serve.config.settings import (
    APIConfig,
    DatabaseConfig,
    SecurityConfig,
    Settings,
)
from picosentry.serve.profiles import (
    ProfileCheck,
    ProductionProfile,
    ProductionProfileError,
    enforce_production_profile,
    warn_development_profile,
)

ROOT = Path(__file__).parent.parent
os.environ.setdefault(
    "PICOSHOGUN_SECRET_KEY",
    "test-key-for-pytest-at-least-32-bytes!",
)

SECURE_SECURITY = SecurityConfig(
    secret_key="a" * 32,
    ssl_cert_path=Path("/fake/cert.pem"),
    rate_limit_backend="redis",
)
SECURE_API = APIConfig(cors_origins=["https://example.com"])
SECURE_DATABASE = DatabaseConfig(backend="sqlite")

SECURE_ENV = {
    "PICOSHOGUN_ADMIN_API_KEY": "sk_admin_test",
    "PICODOME_POLICY_SIGNING_KEY": "hexkey123",
}


def _make_settings(**overrides) -> Settings:
    kw = {
        "env": "production",
        "security": SECURE_SECURITY,
        "database": SECURE_DATABASE,
        "api": SECURE_API,
    }
    kw.update(overrides)
    return Settings(**kw)


def _insecure_settings() -> Settings:
    return Settings(
        env="production",
        security=SecurityConfig(secret_key=""),
        database=DatabaseConfig(backend="jsonl"),
        api=APIConfig(cors_origins=["*"]),
    )


class TestProductionProfile:
    def test_all_checks_pass(self) -> None:
        s = _make_settings()
        with patch.dict(os.environ, SECURE_ENV):
            assert ProductionProfile(s).check() == []

    def test_missing_secret_key(self) -> None:
        s = _make_settings(
            security=SecurityConfig(
                secret_key="",
                ssl_cert_path=Path("/fake/cert.pem"),
                rate_limit_backend="redis",
            ),
        )
        failures = ProductionProfile(s).check()
        assert any(f.name == "auth" for f in failures)

    def test_weak_secret_key(self) -> None:
        s = _make_settings(
            security=SecurityConfig(
                secret_key="changeme",
                ssl_cert_path=Path("/fake/cert.pem"),
                rate_limit_backend="redis",
            ),
        )
        failures = ProductionProfile(s).check()
        assert any(f.name == "auth" and "weak" in f.message.lower() for f in failures)

    def test_short_secret_key(self) -> None:
        s = _make_settings(
            security=SecurityConfig(
                secret_key="a" * 10,
                ssl_cert_path=Path("/fake/cert.pem"),
                rate_limit_backend="redis",
            ),
        )
        failures = ProductionProfile(s).check()
        assert any(f.name == "auth" and "too short" in f.message.lower() for f in failures)

    def test_cors_wildcard(self) -> None:
        s = _make_settings(api=APIConfig(cors_origins=["*"]))
        failures = ProductionProfile(s).check()
        assert any(f.name == "cors" for f in failures)

    def test_jsonl_backend(self) -> None:
        s = _make_settings(database=DatabaseConfig(backend="jsonl"))
        failures = ProductionProfile(s).check()
        assert any(f.name == "store" for f in failures)

    def test_sqlite_backend_ok(self) -> None:
        s = _make_settings(database=DatabaseConfig(backend="sqlite"))
        with patch.dict(os.environ, SECURE_ENV):
            failures = ProductionProfile(s).check()
        assert not any(f.name == "store" for f in failures)

    def test_postgresql_backend_ok(self) -> None:
        s = _make_settings(database=DatabaseConfig(backend="postgresql"))
        with patch.dict(os.environ, SECURE_ENV):
            failures = ProductionProfile(s).check()
        assert not any(f.name == "store" for f in failures)

    def test_no_tls(self) -> None:
        s = _make_settings(
            security=SecurityConfig(
                secret_key="a" * 32,
                ssl_cert_path=None,
                rate_limit_backend="redis",
            ),
        )
        failures = ProductionProfile(s).check()
        assert any(f.name == "tls" for f in failures)

    def test_memory_rate_limiting(self) -> None:
        s = _make_settings(
            security=SecurityConfig(
                secret_key="a" * 32,
                ssl_cert_path=Path("/fake/cert.pem"),
                rate_limit_backend="memory",
            ),
        )
        failures = ProductionProfile(s).check()
        assert any(f.name == "rate_limiting" for f in failures)

    def test_redis_rate_limiting_ok(self) -> None:
        s = _make_settings()
        with patch.dict(os.environ, SECURE_ENV):
            failures = ProductionProfile(s).check()
        assert not any(f.name == "rate_limiting" for f in failures)

    def test_no_policy_signing_key(self) -> None:
        s = _make_settings()
        with patch.dict(os.environ, {"PICODOME_POLICY_SIGNING_KEY": ""}):
            failures = ProductionProfile(s).check()
        assert any(f.name == "policy_signing" for f in failures)

    def test_policy_signing_key_set(self) -> None:
        s = _make_settings()
        with patch.dict(os.environ, {"PICODOME_POLICY_SIGNING_KEY": "hexkey123"}):
            failures = ProductionProfile(s).check()
        assert not any(f.name == "policy_signing" for f in failures)

    def test_no_admin_api_key(self) -> None:
        s = _make_settings()
        with patch.dict(os.environ, {"PICOSHOGUN_ADMIN_API_KEY": ""}):
            failures = ProductionProfile(s).check()
        assert any(f.name == "admin_auth" for f in failures)

    def test_admin_api_key_set(self) -> None:
        s = _make_settings()
        with patch.dict(os.environ, {"PICOSHOGUN_ADMIN_API_KEY": "sk_admin_test"}):
            failures = ProductionProfile(s).check()
        assert not any(f.name == "admin_auth" for f in failures)


class TestProductionProfileError:
    def test_error_lists_all_failures(self) -> None:
        failures = [
            ProfileCheck("cors", "wildcard"),
            ProfileCheck("tls", "no cert"),
        ]
        err = ProductionProfileError(failures)
        assert "cors" in str(err)
        assert "tls" in str(err)
        assert err.failures is failures

    def test_enforce_raises_on_failures(self) -> None:
        s = _insecure_settings()
        with pytest.raises(ProductionProfileError) as exc_info:
            enforce_production_profile(s)
        assert len(exc_info.value.failures) >= 3

    def test_enforce_passes_on_secure(self) -> None:
        s = _make_settings()
        with patch.dict(os.environ, SECURE_ENV):
            enforce_production_profile(s)


class TestDevelopmentProfile:
    def test_warn_logs_failures(self, caplog: pytest.LogCaptureFixture) -> None:
        s = _insecure_settings()
        with caplog.at_level(logging.WARNING, logger="picoshogun.profiles"):
            warn_development_profile(s)
        assert any("DEVELOPMENT PROFILE" in r.message for r in caplog.records)

    def test_warn_no_failures_no_output(self, caplog: pytest.LogCaptureFixture) -> None:
        s = _make_settings()
        with patch.dict(os.environ, SECURE_ENV), caplog.at_level(logging.WARNING, logger="picoshogun.profiles"):
            warn_development_profile(s)
        assert not any("DEVELOPMENT PROFILE" in r.message for r in caplog.records)


class TestMultipleFailures:
    def test_all_insecure_at_once(self) -> None:
        s = _insecure_settings()
        with patch.dict(
            os.environ,
            {
                "PICOSHOGUN_ADMIN_API_KEY": "",
                "PICODOME_POLICY_SIGNING_KEY": "",
            },
        ):
            failures = ProductionProfile(s).check()
        names = {f.name for f in failures}
        for expected in {
            "auth",
            "cors",
            "store",
            "tls",
            "rate_limiting",
            "policy_signing",
            "admin_auth",
        }:
            assert expected in names, f"missing check: {expected}"
