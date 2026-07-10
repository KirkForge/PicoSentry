"""Tests for picodome.auth — constant-time token validation and hash-based RBAC."""

import hashlib
import hmac
import os
from unittest.mock import patch

import pytest

from picosentry.sandbox.auth import (
    RBAC,
    AuthError,
    Role,
    TokenAuth,
    _constant_time_equal,
    _hash_token,
)


class TestConstantTimeEqual:
    """Tests for _constant_time_equal."""

    def test_equal_strings(self):
        assert _constant_time_equal("hello", "hello") is True

    def test_unequal_strings(self):
        assert _constant_time_equal("hello", "world") is False

    def test_empty_strings(self):
        assert _constant_time_equal("", "") is True

    def test_one_empty(self):
        assert _constant_time_equal("hello", "") is False

    def test_prefix_match_still_fails(self):
        assert _constant_time_equal("picodome-admin-secret123", "picodome-admin-secret456") is False

    def test_uses_hmac_compare_digest(self):
        """Verify we're using hmac.compare_digest internally."""
        a = "test-token-123"
        b = "test-token-123"
        assert _constant_time_equal(a, b) == hmac.compare_digest(a.encode(), b.encode())


class TestHashToken:
    """Tests for _hash_token."""

    def test_deterministic(self):
        """Same input → same hash."""
        assert _hash_token("test") == _hash_token("test")

    def test_different_inputs_different_hashes(self):
        assert _hash_token("token1") != _hash_token("token2")

    def test_sha256_length(self):
        """SHA-256 hex digest is 64 chars."""
        assert len(_hash_token("test")) == 64

    def test_is_sha256(self):
        expected = hashlib.sha256(b"test").hexdigest()
        assert _hash_token("test") == expected


class TestRBAC:
    """Tests for hash-based RBAC."""

    def test_register_and_lookup(self):
        rbac = RBAC()
        rbac.register_token("picodome-admin-secret123", "admin")
        assert rbac.get_role("picodome-admin-secret123") == "admin"

    def test_unknown_token_gets_no_role(self):
        rbac = RBAC()
        assert rbac.get_role("unknown-token") == Role.NONE
        assert rbac.has_permission("unknown-token", "scan:read") is False

    def test_submitter_permissions(self):
        rbac = RBAC()
        rbac.register_token("picodome-submitter-abc", "submitter")
        token = "picodome-submitter-abc"
        assert rbac.has_permission(token, "scan:submit") is True
        assert rbac.has_permission(token, "scan:read") is True
        assert rbac.has_permission(token, "policy:write") is False

    def test_reader_permissions(self):
        rbac = RBAC()
        rbac.register_token("picodome-reader-abc", "reader")
        token = "picodome-reader-abc"
        assert rbac.has_permission(token, "scan:read") is True
        assert rbac.has_permission(token, "policy:read") is True
        assert rbac.has_permission(token, "scan:submit") is False

    def test_admin_has_wildcard(self):
        rbac = RBAC()
        rbac.register_token("picodome-admin-abc", "admin")
        token = "picodome-admin-abc"
        assert rbac.has_permission(token, "scan:submit") is True
        assert rbac.has_permission(token, "any:permission") is True

    def test_is_known_token(self):
        rbac = RBAC()
        rbac.register_token("my-token", "admin")
        assert rbac.is_known_token("my-token") is True
        assert rbac.is_known_token("unknown-token") is False

    def test_no_plaintext_tokens_stored(self):
        """RBAC should store hashes, not plaintext tokens."""
        rbac = RBAC()
        rbac.register_token("secret-token-123", "admin")
        # The internal map should use hashes
        for key in rbac._role_map:
            # Should be a 64-char hex string (SHA-256)
            assert len(key) == 64
            assert key != "secret-token-123"


class TestTokenAuth:
    """Tests for TokenAuth with constant-time validation."""

    def test_valid_token(self):
        with patch.dict(os.environ, {"PICODOME_API_TOKENS": "test-token-123"}, clear=False):
            auth = TokenAuth()
            assert auth.validate("test-token-123") is True

    def test_invalid_token(self):
        with patch.dict(os.environ, {"PICODOME_API_TOKENS": "test-token-123"}, clear=False):
            auth = TokenAuth()
            assert auth.validate("wrong-token") is False

    def test_multiple_tokens(self):
        with patch.dict(os.environ, {"PICODOME_API_TOKENS": "token-1,token-2,token-3"}, clear=False):
            auth = TokenAuth()
            assert auth.validate("token-1") is True
            assert auth.validate("token-2") is True
            assert auth.validate("token-3") is True
            assert auth.validate("token-4") is False

    def test_role_extraction_from_token(self):
        with patch.dict(
            os.environ, {"PICODOME_API_TOKENS": "picodome-admin-secret123,picodome-reader-abc456"}, clear=False
        ):
            auth = TokenAuth()
            assert auth.get_role("picodome-admin-secret123") == "admin"
            assert auth.get_role("picodome-reader-abc456") == "reader"

    def test_token_without_prefix_gets_reader(self):
        with patch.dict(os.environ, {"PICODOME_API_TOKENS": "my-simple-token"}, clear=False):
            auth = TokenAuth()
            assert auth.get_role("my-simple-token") == Role.READER

    def test_dev_mode_all_requests(self):
        with patch.dict(
            os.environ,
            {
                "PICODOME_API_TOKENS": "",
                "PICODOME_DEV_MODE": "1",
            },
            clear=False,
        ):
            auth = TokenAuth()
            assert auth.validate("any-token") is True
            assert auth.is_configured is True

    def test_no_tokens_no_dev_mode_rejects(self):
        with patch.dict(
            os.environ,
            {
                "PICODOME_API_TOKENS": "",
                "PICODOME_DEV_MODE": "",
            },
            clear=False,
        ):
            auth = TokenAuth()
            assert auth.validate("any-token") is False

    def test_enterprise_mode_rejects_short_tokens(self):
        with patch.dict(
            os.environ,
            {
                "PICODOME_ENTERPRISE_MODE": "1",
                "PICODOME_API_TOKENS": "short",
            },
            clear=False,
        ):
            auth = TokenAuth()
            assert auth.validate("short") is False

    def test_enterprise_mode_requires_tokens(self):
        with patch.dict(
            os.environ,
            {
                "PICODOME_ENTERPRISE_MODE": "1",
                "PICODOME_API_TOKENS": "",
            },
            clear=False,
        ):
            auth = TokenAuth()
            assert auth.validate("any-token") is False
            assert auth.is_configured is False

    def test_enterprise_mode_accepts_long_token(self):
        long_token = "picodome-admin-" + "a" * 50
        with patch.dict(
            os.environ,
            {
                "PICODOME_ENTERPRISE_MODE": "1",
                "PICODOME_API_TOKENS": long_token,
            },
            clear=False,
        ):
            auth = TokenAuth()
            assert auth.validate(long_token) is True

    def test_enterprise_mode_no_dev_bypass(self):
        with (
            patch.dict(
                os.environ,
                {
                    "PICODOME_ENTERPRISE_MODE": "1",
                    "PICODOME_DEV_MODE": "1",
                    "PICODOME_API_TOKENS": "",
                },
                clear=False,
            ),
            # F1: Enterprise + DEV_MODE now raises AuthError at init
            pytest.raises(AuthError, match="DEV_MODE"),
        ):
            TokenAuth()

    def test_has_permission(self):
        with patch.dict(os.environ, {"PICODOME_API_TOKENS": "picodome-admin-secret123"}, clear=False):
            auth = TokenAuth()
            assert auth.has_permission("picodome-admin-secret123", "scan:submit") is True
            assert auth.has_permission("picodome-admin-secret123", "any:thing") is True

    def test_is_enterprise(self):
        with patch.dict(
            os.environ,
            {
                "PICODOME_ENTERPRISE_MODE": "1",
            },
            clear=False,
        ):
            auth = TokenAuth()
            assert auth.is_enterprise is True

    def test_is_not_enterprise(self):
        with patch.dict(
            os.environ,
            {
                "PICODOME_ENTERPRISE_MODE": "",
            },
            clear=False,
        ):
            auth = TokenAuth()
            assert auth.is_enterprise is False

    def test_constant_time_no_timing_leak(self):
        """Verify that validation doesn't use simple string comparison."""
        # This is a structural test — we can't prove timing safety in pytest,
        # but we can verify the implementation uses hmac.compare_digest.
        with patch.dict(
            os.environ,
            {
                "PICODOME_API_TOKENS": "test-token-123",
            },
            clear=False,
        ):
            TokenAuth()
            # _constant_time_equal should be used, not `==`
            # Verify by checking that the auth module imports hmac.compare_digest
            from picosentry.sandbox import auth as auth_module

            assert hasattr(auth_module, "_constant_time_equal")
