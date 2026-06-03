"""Tests for the notary module (Rekor/Sigstore transparency log integration).

All HTTP calls are mocked — tests must work without a live Rekor instance.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from picosentry.sandbox.audit import AuditEventType, AuditLogger
from picosentry.sandbox.notary import (
    AuditNotary,
    NotaryConnectionError,
    NotaryError,
    NotaryTimeoutError,
    NotaryVerificationError,
    NullNotary,
    RekorNotary,
    get_default_notary,
    set_default_notary,
    sign_entry,
    verify_entry_signature,
)

# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def sample_entry():
    """A sample audit entry dict."""
    return {
        "event_type": "scan_start",
        "actor": "ci-pipeline",
        "detail": "npm install test-package",
        "target": "test-package",
        "metadata": {"verdict": "DENY"},
    }


@pytest.fixture
def sample_entry_2():
    """A second sample audit entry dict (different content)."""
    return {
        "event_type": "scan_complete",
        "actor": "ci-pipeline",
        "detail": "scan completed",
        "target": "test-package",
        "metadata": {"verdict": "ALLOW"},
    }


@pytest.fixture
def null_notary():
    """A NullNotary instance."""
    return NullNotary()


@pytest.fixture
def null_notary_custom_key():
    """A NullNotary with a custom HMAC key."""
    return NullNotary(hmac_key="my-custom-secret-key")


@pytest.fixture
def rekor_notary():
    """A RekorNotary instance (will not make real HTTP calls in tests)."""
    return RekorNotary(
        rekor_url="https://rekor.example.com",
        timeout=5,
        hmac_key="test-hmac-key",
    )


@pytest.fixture
def audit_dir(tmp_path):
    """Temporary audit directory."""
    return tmp_path / "audit"


# ─── HMAC-SHA256 Signing Tests ───────────────────────────────────────────────


class TestHMACSigning:
    """Tests for the HMAC-SHA256 signing functions."""

    def test_sign_entry_deterministic(self, sample_entry):
        """Same entry + same key = same signature."""
        sig1 = sign_entry(sample_entry)
        sig2 = sign_entry(sample_entry)
        assert sig1 == sig2

    def test_sign_entry_different_keys(self, sample_entry):
        """Different keys produce different signatures."""
        sig1 = sign_entry(sample_entry, key="key-a")
        sig2 = sign_entry(sample_entry, key="key-b")
        assert sig1 != sig2

    def test_sign_entry_different_entries(self, sample_entry, sample_entry_2):
        """Different entries produce different signatures."""
        sig1 = sign_entry(sample_entry)
        sig2 = sign_entry(sample_entry_2)
        assert sig1 != sig2

    def test_sign_entry_is_hex_sha256_hmac(self, sample_entry):
        """Signature is a hex-encoded SHA-256 HMAC (64 chars)."""
        sig = sign_entry(sample_entry)
        assert len(sig) == 64
        assert all(c in "0123456789abcdef" for c in sig)

    def test_sign_entry_key_order_independent(self):
        """JSON key ordering doesn't affect the signature (sorted)."""
        entry_a = {"z": 1, "a": 2, "m": 3}
        entry_b = {"a": 2, "m": 3, "z": 1}
        assert sign_entry(entry_a) == sign_entry(entry_b)

    def test_verify_entry_signature_valid(self, sample_entry):
        """Valid signature verifies correctly."""
        sig = sign_entry(sample_entry)
        assert verify_entry_signature(sample_entry, sig) is True

    def test_verify_entry_signature_invalid(self, sample_entry):
        """Wrong signature fails verification."""
        sig = sign_entry(sample_entry)
        # Modify the entry
        tampered = dict(sample_entry)
        tampered["detail"] = "TAMPERED"
        assert verify_entry_signature(tampered, sig) is False

    def test_verify_entry_signature_wrong_key(self, sample_entry):
        """Signature with wrong key fails verification."""
        sig = sign_entry(sample_entry, key="correct-key")
        assert verify_entry_signature(sample_entry, sig, key="wrong-key") is False

    def test_verify_entry_signature_tampered_content(self, sample_entry):
        """Tampered content fails verification against original signature."""
        sig = sign_entry(sample_entry)
        tampered = dict(sample_entry)
        tampered["metadata"] = {"verdict": "ALLOW"}
        assert verify_entry_signature(tampered, sig) is False


# ─── NullNotary Tests ───────────────────────────────────────────────────────


class TestNullNotary:
    """Tests for the NullNotary (offline/air-gapped mode)."""

    def test_submit_returns_uuid(self, null_notary, sample_entry):
        """submit_entry returns a UUID string."""
        uuid = null_notary.submit_entry(sample_entry)
        assert isinstance(uuid, str)
        assert len(uuid) == 36  # UUID4 format

    def test_submit_and_verify(self, null_notary, sample_entry):
        """Submit then verify an entry."""
        uuid = null_notary.submit_entry(sample_entry)
        assert null_notary.verify_entry(uuid, sample_entry) is True

    def test_verify_unknown_uuid(self, null_notary, sample_entry):
        """Verifying an unknown UUID returns False."""
        assert null_notary.verify_entry("nonexistent-uuid", sample_entry) is False

    def test_verify_tampered_entry(self, null_notary, sample_entry):
        """Verifying a tampered entry returns False."""
        uuid = null_notary.submit_entry(sample_entry)
        tampered = dict(sample_entry)
        tampered["detail"] = "TAMPERED"
        assert null_notary.verify_entry(uuid, tampered) is False

    def test_get_proof_submitted_entry(self, null_notary, sample_entry):
        """get_proof returns proof for a submitted entry."""
        uuid = null_notary.submit_entry(sample_entry)
        proof = null_notary.get_proof(uuid)
        assert proof["uuid"] == uuid
        assert proof["notary"] == "null"
        assert "hmac_signature" in proof
        assert "submitted_at" in proof

    def test_get_proof_unknown_uuid(self, null_notary):
        """get_proof for unknown UUID returns error."""
        proof = null_notary.get_proof("nonexistent-uuid")
        assert "error" in proof

    def test_multiple_entries_independent(self, null_notary, sample_entry, sample_entry_2):
        """Multiple entries have independent UUIDs and signatures."""
        uuid1 = null_notary.submit_entry(sample_entry)
        uuid2 = null_notary.submit_entry(sample_entry_2)
        assert uuid1 != uuid2
        assert null_notary.verify_entry(uuid1, sample_entry) is True
        assert null_notary.verify_entry(uuid2, sample_entry_2) is True
        # Cross-verification should fail
        assert null_notary.verify_entry(uuid1, sample_entry_2) is False

    def test_custom_hmac_key(self, null_notary_custom_key, sample_entry):
        """NullNotary with custom HMAC key signs correctly."""
        uuid = null_notary_custom_key.submit_entry(sample_entry)
        assert null_notary_custom_key.verify_entry(uuid, sample_entry) is True

    def test_proof_signature_matches_sign_entry(self, null_notary, sample_entry):
        """The HMAC signature in the proof matches sign_entry()."""
        uuid = null_notary.submit_entry(sample_entry)
        proof = null_notary.get_proof(uuid)
        expected_sig = sign_entry(sample_entry)
        assert proof["hmac_signature"] == expected_sig


# ─── RekorNotary Tests (with mocked HTTP) ────────────────────────────────────


class TestRekorNotary:
    """Tests for the RekorNotary (mocked HTTP calls)."""

    def test_submit_success(self, rekor_notary, sample_entry):
        """Successful submission to Rekor returns a UUID."""
        mock_response = MagicMock()
        mock_response.status = 201
        mock_response.read.return_value = json.dumps(
            {
                "rekor-uuid-12345": {
                    "body": "...",
                    "integratedTime": 1700000000,
                }
            }
        ).encode("utf-8")
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            uuid = rekor_notary.submit_entry(sample_entry)
            assert uuid == "rekor-uuid-12345"

    def test_submit_fallback_on_connection_error(self, rekor_notary, sample_entry):
        """RekorNotary falls back to local UUID when Rekor is unavailable."""
        with patch("urllib.request.urlopen", side_effect=Exception("Connection refused")):
            uuid = rekor_notary.submit_entry(sample_entry)
            assert isinstance(uuid, str)
            assert len(uuid) == 36  # Local UUID format
            # Verify it was stored as a fallback entry
            proof = rekor_notary.get_proof(uuid)
            assert proof["notary"] == "rekor-fallback"

    def test_submit_fallback_on_timeout(self, rekor_notary, sample_entry):
        """RekorNotary falls back on timeout."""
        import urllib.error

        error = urllib.error.URLError("timed out")
        with patch("urllib.request.urlopen", side_effect=error):
            uuid = rekor_notary.submit_entry(sample_entry)
            assert isinstance(uuid, str)
            proof = rekor_notary.get_proof(uuid)
            assert proof["notary"] == "rekor-fallback"

    def test_verify_submitted_entry(self, rekor_notary, sample_entry):
        """Verify an entry that was submitted successfully."""
        mock_response = MagicMock()
        mock_response.status = 201
        mock_response.read.return_value = json.dumps(
            {
                "rekor-uuid-verify": {
                    "body": "...",
                }
            }
        ).encode("utf-8")
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            uuid = rekor_notary.submit_entry(sample_entry)

        # Verify locally (no HTTP needed for local verification)
        result = rekor_notary.verify_entry(uuid, sample_entry)
        assert result is True

    def test_verify_fallback_entry(self, rekor_notary, sample_entry):
        """Verify an entry that fell back to local UUID."""
        with patch("urllib.request.urlopen", side_effect=Exception("offline")):
            uuid = rekor_notary.submit_entry(sample_entry)

        result = rekor_notary.verify_entry(uuid, sample_entry)
        assert result is True

    def test_get_proof_submitted(self, rekor_notary, sample_entry):
        """get_proof returns proof for a successfully submitted entry."""
        mock_response = MagicMock()
        mock_response.status = 201
        mock_response.read.return_value = json.dumps(
            {
                "rekor-proof-uuid": {
                    "body": "...",
                }
            }
        ).encode("utf-8")
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            uuid = rekor_notary.submit_entry(sample_entry)

        proof = rekor_notary.get_proof(uuid)
        assert proof["uuid"] == uuid
        assert "hmac_signature" in proof

    def test_get_proof_fallback_entry(self, rekor_notary, sample_entry):
        """get_proof for a fallback entry (Rekor unavailable)."""
        with patch("urllib.request.urlopen", side_effect=Exception("offline")):
            uuid = rekor_notary.submit_entry(sample_entry)

        proof = rekor_notary.get_proof(uuid)
        assert proof["uuid"] == uuid
        assert proof["notary"] == "rekor-fallback"
        assert "hmac_signature" in proof

    def test_hmac_signature_always_computed(self, rekor_notary, sample_entry):
        """HMAC signature is computed even when Rekor fails."""
        with patch("urllib.request.urlopen", side_effect=Exception("offline")):
            uuid = rekor_notary.submit_entry(sample_entry)

        proof = rekor_notary.get_proof(uuid)
        assert proof["hmac_signature"] == sign_entry(sample_entry, key="test-hmac-key")

    def test_custom_rekor_url(self, sample_entry):
        """RekorNotary uses custom URL."""
        notary = RekorNotary(rekor_url="https://custom-rekor.example.com")
        assert notary._rekor_url == "https://custom-rekor.example.com"

    def test_custom_timeout(self, sample_entry):
        """RekorNotary uses custom timeout."""
        notary = RekorNotary(timeout=30)
        assert notary._timeout == 30


# ─── Exception Tests ─────────────────────────────────────────────────────────


class TestNotaryExceptions:
    """Tests for notary exception hierarchy."""

    def test_notary_error_hierarchy(self):
        """All specific exceptions inherit from NotaryError."""
        assert issubclass(NotaryTimeoutError, NotaryError)
        assert issubclass(NotaryConnectionError, NotaryError)
        assert issubclass(NotaryVerificationError, NotaryError)

    def test_notary_timeout_error_message(self):
        """NotaryTimeoutError carries a message."""
        exc = NotaryTimeoutError("request timed out")
        assert "timed out" in str(exc)

    def test_notary_connection_error_message(self):
        """NotaryConnectionError carries a message."""
        exc = NotaryConnectionError("connection refused")
        assert "connection refused" in str(exc)


# ─── Audit-Notary Integration Tests ─────────────────────────────────────────


class TestAuditNotaryIntegration:
    """Tests for the integration between AuditLogger and notary."""

    def test_audit_with_null_notary(self, audit_dir):
        """AuditLogger with NullNotary records and notarizes events."""
        notary = NullNotary()
        audit = AuditLogger(log_dir=audit_dir, notary=notary)

        event = audit.record(
            event_type=AuditEventType.SCAN_START,
            actor="test-user",
            detail="test scan",
            target="test-pkg",
        )
        # Event should be recorded normally
        assert event.event_type == AuditEventType.SCAN_START

        # Verify chain integrity is still intact
        violations = audit.verify_chain()
        assert violations == []

    def test_audit_with_notary_notarizes(self, audit_dir):
        """AuditLogger with notary calls submit_entry for each event."""
        mock_notary = MagicMock(spec=AuditNotary)
        mock_notary.submit_entry.return_value = "test-uuid-123"

        audit = AuditLogger(log_dir=audit_dir, notary=mock_notary)
        audit.record(
            event_type=AuditEventType.SCAN_START,
            actor="test-user",
            detail="test scan",
        )

        # submit_entry should have been called
        mock_notary.submit_entry.assert_called_once()

    def test_audit_notary_failure_does_not_crash(self, audit_dir):
        """If notary raises, the audit logger still records the event."""
        mock_notary = MagicMock(spec=AuditNotary)
        mock_notary.submit_entry.side_effect = ConnectionError("Rekor down")

        audit = AuditLogger(log_dir=audit_dir, notary=mock_notary)
        # Should NOT raise
        event = audit.record(
            event_type=AuditEventType.SCAN_START,
            actor="test-user",
            detail="test scan",
        )
        assert event.event_type == AuditEventType.SCAN_START

    def test_audit_without_notary(self, audit_dir):
        """AuditLogger without notary works normally."""
        audit = AuditLogger(log_dir=audit_dir)
        event = audit.record(
            event_type=AuditEventType.SCAN_START,
            actor="test-user",
            detail="test scan",
        )
        assert event.event_type == AuditEventType.SCAN_START

        violations = audit.verify_chain()
        assert violations == []

    def test_audit_notary_receives_entry_dict(self, audit_dir):
        """Notary receives the full event dict."""
        mock_notary = MagicMock(spec=AuditNotary)
        mock_notary.submit_entry.return_value = "uuid-1"

        audit = AuditLogger(log_dir=audit_dir, notary=mock_notary)
        audit.record(
            event_type=AuditEventType.SCAN_COMPLETE,
            actor="ci",
            detail="done",
            target="pkg",
        )

        call_args = mock_notary.submit_entry.call_args[0][0]
        assert isinstance(call_args, dict)
        assert call_args["event_type"] == "scan_complete"
        assert call_args["actor"] == "ci"

    def test_multiple_events_notarized(self, audit_dir):
        """Multiple events are all notarized."""
        mock_notary = MagicMock(spec=AuditNotary)
        mock_notary.submit_entry.return_value = "uuid"

        audit = AuditLogger(log_dir=audit_dir, notary=mock_notary)
        audit.record(event_type=AuditEventType.SCAN_START, actor="u1", detail="start")
        audit.record(event_type=AuditEventType.SCAN_COMPLETE, actor="u1", detail="done")
        audit.record(event_type=AuditEventType.POLICY_UPDATE, actor="admin", detail="update")

        assert mock_notary.submit_entry.call_count == 3


# ─── Default Notary Module-level Tests ────────────────────────────────────────


class TestDefaultNotary:
    """Tests for module-level default notary management."""

    def test_default_notary_is_null(self):
        """Default notary is NullNotary (offline mode)."""
        # Reset global state
        import picosentry.sandbox.notary.rekor as rekor_mod

        rekor_mod._default_notary = None
        notary = get_default_notary()
        assert isinstance(notary, NullNotary)

    def test_set_default_notary(self):
        """set_default_notary changes the global notary."""
        import picosentry.sandbox.notary.rekor as rekor_mod

        rekor_mod._default_notary = None
        custom = NullNotary(hmac_key="custom-key")
        set_default_notary(custom)
        assert get_default_notary() is custom

    def test_set_default_notary_rekor(self):
        """Can set a RekorNotary as default."""
        import picosentry.sandbox.notary.rekor as rekor_mod

        rekor_notary = RekorNotary(rekor_url="https://rekor.test.com")
        set_default_notary(rekor_notary)
        assert isinstance(get_default_notary(), RekorNotary)
        # Reset
        rekor_mod._default_notary = None


# ─── ABC Enforcement Tests ──────────────────────────────────────────────────


class TestAuditNotaryABC:
    """Tests for the AuditNotary abstract base class."""

    def test_cannot_instantiate_abc(self):
        """AuditNotary ABC cannot be instantiated directly."""
        with pytest.raises(TypeError):
            AuditNotary()

    def test_null_notary_is_audit_notary(self, null_notary):
        """NullNotary implements AuditNotary."""
        assert isinstance(null_notary, AuditNotary)

    def test_rekor_notary_is_audit_notary(self, rekor_notary):
        """RekorNotary implements AuditNotary."""
        assert isinstance(rekor_notary, AuditNotary)


# ─── Rekor HTTP Error Path Tests ────────────────────────────────────────────


class TestRekorHTTPErrorPaths:
    """Test Rekor HTTP error handling with mocked urllib."""

    def test_connection_refused_fallback(self, rekor_notary, sample_entry):
        """Connection refused falls back to local UUID."""
        import urllib.error

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            uuid = rekor_notary.submit_entry(sample_entry)
            assert len(uuid) == 36  # Local UUID

    def test_timeout_fallback(self, rekor_notary, sample_entry):
        """Timeout falls back to local UUID."""
        import urllib.error

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timed out")):
            uuid = rekor_notary.submit_entry(sample_entry)
            assert len(uuid) == 36

    def test_dns_failure_fallback(self, rekor_notary, sample_entry):
        """DNS failure falls back to local UUID."""
        import urllib.error

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Name or service not known")):
            uuid = rekor_notary.submit_entry(sample_entry)
            assert len(uuid) == 36

    def test_verify_unknown_uuid_rekor(self, rekor_notary, sample_entry):
        """Verify unknown UUID tries Rekor then fails gracefully."""
        import urllib.error

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("not found")):
            result = rekor_notary.verify_entry("unknown-uuid", sample_entry)
            assert result is False

    def test_get_proof_unknown_uuid_rekor(self, rekor_notary):
        """get_proof for unknown UUID returns error."""
        import urllib.error

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("not found")):
            proof = rekor_notary.get_proof("unknown-uuid")
            assert "error" in proof
