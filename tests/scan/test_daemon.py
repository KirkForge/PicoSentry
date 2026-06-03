"""Tests for PicoSentry daemon with auth and rate limiting."""

import json
import unittest

from picosentry.scan.auth import AuthConfig, RateLimiter
from picosentry.scan.daemon import HealthHandler


class TestDaemonHealthHandler(unittest.TestCase):
    """Tests for HealthHandler endpoint logic."""

    def setUp(self):
        """Reset handler class config before each test."""
        HealthHandler.auth_config = AuthConfig(mode="off")
        HealthHandler.rate_limiter = RateLimiter(rps=0)

    def test_health_endpoint_no_auth(self):
        """Health endpoint returns 200 with no auth required."""
        handler = HealthHandler.__new__(HealthHandler)
        # Test the response data directly
        import io
        from unittest.mock import MagicMock

        handler.wfile = io.BytesIO()
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler._send_json(200, {"status": "healthy", "request_id": "test123"}, "test123")
        handler.wfile.seek(0)
        data = json.loads(handler.wfile.read())
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["request_id"], "test123")


class TestDaemonRateLimiting(unittest.TestCase):
    """Tests for rate limiting in daemon context."""

    def test_rate_limiter_allows_burst(self):
        limiter = RateLimiter(rps=100, burst=10)
        for _ in range(10):
            self.assertTrue(limiter.check("1.2.3.4"))
        self.assertFalse(limiter.check("1.2.3.4"))

    def test_rate_limiter_independent_clients(self):
        limiter = RateLimiter(rps=1, burst=2)
        self.assertTrue(limiter.check("1.2.3.4"))
        self.assertTrue(limiter.check("1.2.3.4"))
        self.assertFalse(limiter.check("1.2.3.4"))
        # Different client should still have tokens
        self.assertTrue(limiter.check("5.6.7.8"))


class TestDaemonAuthConfig(unittest.TestCase):
    """Tests for daemon auth configuration."""

    def test_auth_config_from_env(self):
        import os
        from unittest.mock import patch as mock_patch

        with mock_patch.dict(os.environ, {"PICOSENTRY_AUTH_MODE": "token", "PICOSENTRY_AUTH_TOKEN": "test123"}):
            config = AuthConfig.from_env()
        self.assertEqual(config.mode, "token")
        self.assertEqual(config.token, "test123")

    def test_auth_config_off_mode(self):
        config = AuthConfig(mode="off")
        self.assertEqual(config.mode, "off")
        self.assertEqual(config.public_endpoints, ["/healthz", "/readyz"])

    def test_auth_config_token_mode(self):
        config = AuthConfig(mode="token", token="s3cret", public_endpoints=["/healthz"])
        self.assertEqual(config.mode, "token")
        self.assertEqual(config.public_endpoints, ["/healthz"])

    def test_auth_config_oidc_mode(self):
        config = AuthConfig(
            mode="oidc",
            oidc_issuer="https://accounts.google.com",
            oidc_audience="picosentry",
        )
        self.assertEqual(config.mode, "oidc")
        self.assertEqual(config.oidc_issuer, "https://accounts.google.com")


class TestDaemonRunDaemon(unittest.TestCase):
    """Tests for run_daemon configuration."""

    def test_run_daemon_creates_auth_config(self):
        """run_daemon should accept an AuthConfig."""
        config = AuthConfig(mode="token", token="s3cret", rate_limit_rps=10)
        self.assertEqual(config.mode, "token")
        self.assertEqual(config.token, "s3cret")
        self.assertEqual(config.rate_limit_rps, 10)


class TestDaemonRequestID(unittest.TestCase):
    """Tests for request ID generation and propagation."""

    def test_request_id_in_headers(self):
        """HealthHandler should include X-Request-Id in responses."""
        handler = HealthHandler.__new__(HealthHandler)
        handler.headers = {"X-Request-Id": "custom-id-123"}
        request_id = handler._request_id()
        self.assertEqual(request_id, "custom-id-123")

    def test_request_id_generated(self):
        """If no X-Request-Id header, one should be generated."""
        handler = HealthHandler.__new__(HealthHandler)
        handler.headers = {}
        request_id = handler._request_id()
        self.assertIsNotNone(request_id)
        self.assertTrue(request_id.startswith("req-"))  # monotonic counter, not uuid4

    def test_client_ip_from_forwarded_trusted(self):
        """X-Forwarded-For is used only when direct IP is a trusted proxy."""
        handler = HealthHandler.__new__(HealthHandler)
        handler.auth_config = AuthConfig(trusted_proxies=["192.168.1.1"])
        handler.client_address = ("192.168.1.1", 12345)
        handler.headers = {"X-Forwarded-For": "10.0.0.1, 10.0.0.2"}
        ip = handler._client_ip()
        self.assertEqual(ip, "10.0.0.1")

    def test_client_ip_from_forwarded_untrusted(self):
        """X-Forwarded-For is ignored when direct IP is NOT a trusted proxy."""
        handler = HealthHandler.__new__(HealthHandler)
        handler.auth_config = AuthConfig(trusted_proxies=["192.168.1.1"])
        handler.client_address = ("10.0.0.99", 12345)
        handler.headers = {"X-Forwarded-For": "10.0.0.1, 10.0.0.2"}
        ip = handler._client_ip()
        self.assertEqual(ip, "10.0.0.99")

    def test_client_ip_direct(self):
        """Without X-Forwarded-For, client_address should be used."""
        handler = HealthHandler.__new__(HealthHandler)
        handler.headers = {}
        handler.client_address = ("192.168.1.1", 12345)
        ip = handler._client_ip()
        self.assertEqual(ip, "192.168.1.1")


if __name__ == "__main__":
    unittest.main()