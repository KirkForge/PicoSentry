"""Tests for PicoSentry auth module."""

import json
import os
import time
import unittest
from unittest.mock import patch

from picosentry.scan.auth import (
    AuthConfig,
    AuthResult,
    RateLimiter,
    _constant_time_compare,
    check_auth,
    check_oidc_auth,
    check_token_auth,
)


class TestAuthConfig(unittest.TestCase):
    """Tests for AuthConfig."""

    def test_default_config_is_off(self):
        config = AuthConfig()
        self.assertEqual(config.mode, "off")
        self.assertEqual(config.token, "")
        self.assertEqual(config.public_endpoints, ["/healthz", "/readyz"])
        self.assertEqual(config.rate_limit_rps, 0)

    def test_from_dict(self):
        data = {
            "mode": "token",
            "token": "s3cret",
            "public_endpoints": ["/healthz"],
            "rate_limit_rps": 10,
        }
        config = AuthConfig.from_dict(data)
        self.assertEqual(config.mode, "token")
        self.assertEqual(config.token, "s3cret")
        self.assertEqual(config.public_endpoints, ["/healthz"])
        self.assertEqual(config.rate_limit_rps, 10)

    def test_from_dict_defaults(self):
        config = AuthConfig.from_dict({})
        self.assertEqual(config.mode, "off")
        self.assertEqual(config.public_endpoints, ["/healthz", "/readyz"])

    def test_from_env(self):
        env = {
            "PICOSENTRY_AUTH_MODE": "token",
            "PICOSENTRY_AUTH_TOKEN": "my-token",
            "PICOSENTRY_OIDC_ISSUER": "https://accounts.example.com",
            "PICOSENTRY_OIDC_AUDIENCE": "picosentry",
            "PICOSENTRY_RATE_LIMIT_RPS": "50",
        }
        with patch.dict(os.environ, env, clear=False):
            config = AuthConfig.from_env()
        self.assertEqual(config.mode, "token")
        self.assertEqual(config.token, "my-token")
        self.assertEqual(config.oidc_issuer, "https://accounts.example.com")
        self.assertEqual(config.oidc_audience, "picosentry")
        self.assertEqual(config.rate_limit_rps, 50)

    def test_from_env_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            config = AuthConfig.from_env()
        self.assertEqual(config.mode, "off")
        self.assertEqual(config.token, "")

    def test_from_env_public_endpoints(self):
        env = {"PICOSENTRY_AUTH_PUBLIC_ENDPOINTS": "/healthz,/readyz,/metrics"}
        with patch.dict(os.environ, env, clear=False):
            config = AuthConfig.from_env()
        self.assertEqual(config.public_endpoints, ["/healthz", "/readyz", "/metrics"])


class TestAuthResult(unittest.TestCase):
    """Tests for AuthResult."""

    def test_success(self):
        result = AuthResult.success(identity="user1", token_type="token")
        self.assertTrue(result.ok)
        self.assertEqual(result.identity, "user1")
        self.assertEqual(result.token_type, "token")

    def test_denied(self):
        result = AuthResult.denied("Bad token")
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "Bad token")

    def test_success_with_scopes(self):
        result = AuthResult.success(identity="admin", token_type="oidc", scopes=["read", "write"])
        self.assertEqual(result.scopes, ["read", "write"])


class TestCheckTokenAuth(unittest.TestCase):
    """Tests for token-based authentication."""

    def test_valid_bearer_token(self):
        config = AuthConfig(mode="token", token="s3cret")
        headers = {"authorization": "Bearer s3cret"}
        result = check_token_auth(headers, config)
        self.assertTrue(result.ok)
        # Identity is now token-based: token:s3cret...

    def test_valid_api_key(self):
        config = AuthConfig(mode="token", token="s3cret")
        headers = {"x-api-key": "s3cret"}
        result = check_token_auth(headers, config)
        self.assertTrue(result.ok)

    def test_invalid_token(self):
        config = AuthConfig(mode="token", token="s3cret")
        headers = {"authorization": "Bearer wrong"}
        result = check_token_auth(headers, config)
        self.assertFalse(result.ok)
        self.assertIn("Invalid", result.error)

    def test_missing_header(self):
        config = AuthConfig(mode="token", token="s3cret")
        headers = {}
        result = check_token_auth(headers, config)
        self.assertFalse(result.ok)
        self.assertIn("Missing", result.error)

    def test_no_token_configured(self):
        config = AuthConfig(mode="token", token="")
        headers = {"authorization": "Bearer anything"}
        result = check_token_auth(headers, config)
        self.assertFalse(result.ok)
        self.assertIn("No token", result.error)

    def test_constant_time_compare(self):
        self.assertTrue(_constant_time_compare("abc", "abc"))
        self.assertFalse(_constant_time_compare("abc", "abd"))
        self.assertFalse(_constant_time_compare("short", "much-longer-string"))


class TestCheckOidcAuth(unittest.TestCase):
    """Tests for OIDC/JWT authentication."""

    @staticmethod
    def _has_jwt():
        try:
            import jwt  # noqa: F401
            return True
        except ImportError:
            return False

    def setUp(self):
        if not self._has_jwt():
            self.skipTest("PyJWT not installed")

    def _make_jwt(self, payload: dict) -> str:
        """Create a minimal JWT-like string (header.payload.signature)."""
        import base64

        header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        signature = base64.urlsafe_b64encode(b"fake-signature").rstrip(b"=").decode()
        return f"{header}.{payload_b64}.{signature}"

    def test_missing_auth_header(self):
        config = AuthConfig(mode="oidc", oidc_issuer="https://example.com")
        headers = {}
        result = check_oidc_auth(headers, config)
        self.assertFalse(result.ok)

    def test_expired_token(self):
        payload = {"sub": "user1", "exp": time.time() - 3600, "iss": "https://example.com"}
        token = self._make_jwt(payload)
        config = AuthConfig(mode="oidc", oidc_issuer="https://example.com")
        headers = {"authorization": f"Bearer {token}"}
        # Fail-closed: without JWKS URL, we cannot verify signature, so we reject
        result = check_oidc_auth(headers, config)
        self.assertFalse(result.ok)
        # Without a signing key, we cannot verify the token — fail-closed
        self.assertTrue("signing key" in result.error.lower() or "cannot verify" in result.error.lower())

    def test_wrong_issuer(self):
        payload = {"sub": "user1", "exp": time.time() + 3600, "iss": "https://wrong.com"}
        token = self._make_jwt(payload)
        config = AuthConfig(mode="oidc", oidc_issuer="https://example.com")
        headers = {"authorization": f"Bearer {token}"}
        # Fail-closed: without JWKS URL, we cannot verify signature
        result = check_oidc_auth(headers, config)
        self.assertFalse(result.ok)

    def test_wrong_audience_string(self):
        payload = {"sub": "user1", "exp": time.time() + 3600, "aud": "wrong-audience"}
        token = self._make_jwt(payload)
        config = AuthConfig(mode="oidc", oidc_issuer="https://example.com", oidc_audience="picosentry")
        headers = {"authorization": f"Bearer {token}"}
        result = check_oidc_auth(headers, config)
        self.assertFalse(result.ok)

    def test_correct_audience_list(self):
        payload = {"sub": "user1", "exp": time.time() + 3600, "aud": ["picosentry", "other"]}
        token = self._make_jwt(payload)
        config = AuthConfig(mode="oidc", oidc_issuer="https://example.com", oidc_audience="picosentry")
        headers = {"authorization": f"Bearer {token}"}
        # Without signing key, auth is denied (fail-closed)
        result = check_oidc_auth(headers, config)
        self.assertFalse(result.ok)
        self.assertIn("signing key", result.error.lower())

    def test_valid_claims_denied_without_signing_key(self):
        payload = {"sub": "user1", "exp": time.time() + 3600, "iss": "https://example.com"}
        token = self._make_jwt(payload)
        config = AuthConfig(mode="oidc", oidc_issuer="https://example.com")
        headers = {"authorization": f"Bearer {token}"}
        # Without signing key, auth is denied (fail-closed)
        result = check_oidc_auth(headers, config)
        self.assertFalse(result.ok)
        self.assertIn("signing key", result.error.lower())

    def test_invalid_jwt_format(self):
        config = AuthConfig(mode="oidc")
        headers = {"authorization": "Bearer not-a-jwt"}
        result = check_oidc_auth(headers, config)
        self.assertFalse(result.ok)


class TestCheckAuth(unittest.TestCase):
    """Tests for the main check_auth dispatcher."""

    def test_off_mode_allows_all(self):
        config = AuthConfig(mode="off")
        headers = {}
        result = check_auth(headers, config)
        self.assertTrue(result.ok)
        self.assertEqual(result.identity, "anonymous")

    def test_token_mode(self):
        config = AuthConfig(mode="token", token="s3cret")
        headers = {"authorization": "Bearer s3cret"}
        result = check_auth(headers, config)
        self.assertTrue(result.ok)

    def test_oidc_mode(self):
        config = AuthConfig(mode="oidc")
        # Missing header → denied
        headers = {}
        result = check_auth(headers, config)
        self.assertFalse(result.ok)

    def test_unknown_mode(self):
        config = AuthConfig(mode="unknown")
        headers = {}
        result = check_auth(headers, config)
        self.assertFalse(result.ok)
        self.assertIn("Unknown", result.error)


class TestRateLimiter(unittest.TestCase):
    """Tests for token-bucket rate limiter."""

    def test_unlimited_by_default(self):
        limiter = RateLimiter(rps=0)
        self.assertTrue(limiter.check("1.2.3.4"))
        self.assertTrue(limiter.check("1.2.3.4"))

    def test_rate_limit_enforced(self):
        limiter = RateLimiter(rps=2, burst=2)
        # First two requests should succeed
        self.assertTrue(limiter.check("1.2.3.4"))
        self.assertTrue(limiter.check("1.2.3.4"))
        # Third should be rate-limited
        self.assertFalse(limiter.check("1.2.3.4"))

    def test_separate_clients(self):
        limiter = RateLimiter(rps=1, burst=1)
        self.assertTrue(limiter.check("1.2.3.4"))
        self.assertTrue(limiter.check("5.6.7.8"))  # Different IP

    def test_burst_default(self):
        limiter = RateLimiter(rps=10)
        self.assertEqual(limiter.burst, 20)  # 2x rps

    def test_retry_after(self):
        limiter = RateLimiter(rps=1, burst=1)
        limiter.check("1.2.3.4")  # Use the token
        limiter.check("1.2.3.4")  # Rate limited
        retry = limiter.retry_after("1.2.3.4")
        self.assertGreater(retry, 0)

    def test_retry_after_unlimited(self):
        limiter = RateLimiter(rps=0)
        self.assertEqual(limiter.retry_after("1.2.3.4"), 0)


class TestDaemonAuthIntegration(unittest.TestCase):
    """Integration tests for daemon auth with HealthHandler."""

    def test_health_endpoint_public_by_default(self):
        """Health endpoints should be accessible without auth by default."""
        from picosentry.scan.daemon import HealthHandler

        # Default auth config is "off" — all endpoints accessible
        self.assertEqual(HealthHandler.auth_config.mode, "off")

    def test_metrics_endpoint_requires_auth_in_token_mode(self):
        """When auth is token mode, /metrics should require auth."""
        from picosentry.scan.auth import AuthConfig

        config = AuthConfig(mode="token", token="s3cret")
        self.assertEqual(config.mode, "token")
        self.assertEqual(config.public_endpoints, ["/healthz", "/readyz"])
        self.assertNotIn("/metrics", config.public_endpoints)


if __name__ == "__main__":
    unittest.main()
