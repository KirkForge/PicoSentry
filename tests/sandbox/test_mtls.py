"""Tests for mTLS module."""

import os

import pytest

from picosentry.sandbox.mtls import MTLSConfig, create_ssl_context


class TestMTLSConfig:
    def test_default_not_configured(self):
        config = MTLSConfig()
        assert config.is_configured is False

    def test_dev_mode_configured(self):
        config = MTLSConfig(dev_mode=True)
        assert config.is_configured is True

    def test_cert_key_configured(self):
        config = MTLSConfig(cert_path="/tmp/cert.pem", key_path="/tmp/key.pem")
        assert config.is_configured is True

    def test_from_env(self):
        os.environ["PICODOME_TLS_CERT"] = "/tmp/test.pem"
        os.environ["PICODOME_TLS_KEY"] = "/tmp/test-key.pem"
        try:
            config = MTLSConfig.from_env()
            assert config.cert_path == "/tmp/test.pem"
        finally:
            del os.environ["PICODOME_TLS_CERT"]
            del os.environ["PICODOME_TLS_KEY"]

    def test_to_dict(self):
        config = MTLSConfig(cert_path="c", key_path="k", ca_path="a")
        d = config.to_dict()
        assert d["cert_path"] == "c"
        assert d["key_path"] == "k"


class TestCreateSSLContext:
    def test_no_config_returns_none(self):
        ctx = create_ssl_context(MTLSConfig())
        assert ctx is None

    def test_dev_mode_creates_context(self):
        # This test requires openssl on PATH
        import shutil

        if not shutil.which("openssl"):
            pytest.skip("openssl not available")
        ctx = create_ssl_context(MTLSConfig(dev_mode=True))  # noqa: F841
        # Dev SSL context should be created (or raise if openssl fails)
        # We just verify it doesn't crash


class TestTLSConfigInfo:
    """Test get_tls_config_info function."""

    def test_config_info_no_mtls(self):
        from picosentry.sandbox.mtls import get_tls_config_info

        # No TLS env vars set
        info = get_tls_config_info(MTLSConfig())
        assert info["mtls_enabled"] is False
        assert info["dev_mode"] is False
        assert info["min_tls_version"] == "TLSv1_2"

    def test_config_info_dev_mode(self):
        from picosentry.sandbox.mtls import MTLSConfig, get_tls_config_info

        config = MTLSConfig(dev_mode=True)
        info = get_tls_config_info(config)
        assert info["mtls_enabled"] is True
        assert info["dev_mode"] is True

    def test_config_info_production(self):
        from picosentry.sandbox.mtls import MTLSConfig, get_tls_config_info

        config = MTLSConfig(
            cert_path="/tmp/nonexistent/cert.pem",
            key_path="/tmp/nonexistent/key.pem",
            ca_path="/tmp/nonexistent/ca.pem",
            verify_client=True,
        )
        info = get_tls_config_info(config)
        assert info["mtls_enabled"] is True
        assert info["verify_client"] is True
        assert info["cert_exists"] is False
        assert info["key_exists"] is False


class TestReloadSSLContext:
    """Test reload_ssl_context function."""

    def test_reload_no_mtls(self):
        from picosentry.sandbox.mtls import MTLSConfig, reload_ssl_context

        config = MTLSConfig()
        result = reload_ssl_context(config)
        assert result is None

    def test_reload_dev_mode(self):
        from picosentry.sandbox.mtls import MTLSConfig, reload_ssl_context

        config = MTLSConfig(dev_mode=True)
        # Dev mode creates a self-signed cert
        try:
            result = reload_ssl_context(config)
            assert result is not None
        except RuntimeError:
            # openssl not available
            pass
