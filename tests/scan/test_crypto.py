"""Tests for cryptographic signing and verification of bundles."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from picosentry.scan.crypto import (
    SignatureBundle,
    content_digest,
    content_digest_short,
    embed_signature,
    extract_signature,
    read_detached_signature,
    sign_content,
    verify_content,
    write_detached_signature,
)


class TestSignatureBundle:
    """Tests for SignatureBundle model."""

    def test_defaults(self):
        sb = SignatureBundle()
        assert sb.provider == "none"
        assert sb.raw_signature == ""
        assert sb.is_signed() is False

    def test_signed_bundle(self):
        sb = SignatureBundle(
            signer_identity="test@example.com",
            provider="sigstore",
            raw_signature="base64data==",
            certificate="PEMCERT",
            digest="abc123",
        )
        assert sb.is_signed() is True
        assert sb.provider == "sigstore"

    def test_roundtrip_dict(self):
        sb = SignatureBundle(
            signer_identity="test@example.com",
            provider="sigstore",
            raw_signature="base64data==",
            certificate="PEMCERT",
            digest="abc123",
            signed_at="2026-01-01T00:00:00Z",
        )
        d = sb.to_dict()
        sb2 = SignatureBundle.from_dict(d)
        assert sb2.signer_identity == sb.signer_identity
        assert sb2.provider == sb.provider
        assert sb2.raw_signature == sb.raw_signature
        assert sb2.digest == sb.digest
        assert sb2.signed_at == sb.signed_at

    def test_unsigned_helper(self):
        sb = SignatureBundle.unsigned(digest="sha256:abc")
        assert sb.provider == "none"
        assert sb.digest == "sha256:abc"
        assert sb.is_signed() is False

    def test_to_dict_excludes_none(self):
        sb = SignatureBundle()
        d = sb.to_dict()
        for key in ("signer_identity", "provider", "signature", "certificate", "digest", "signed_at"):
            assert key in d


class TestContentDigest:
    """Tests for content hashing."""

    def test_content_digest_deterministic(self):
        data = b"hello world"
        assert content_digest(data) == content_digest(data)

    def test_content_digest_length(self):
        data = b"test"
        d = content_digest(data)
        assert len(d) == 64  # Full SHA-256 hex

    def test_content_digest_short(self):
        data = b"test"
        ds = content_digest_short(data)
        assert ds.startswith("sha256:")
        assert len(ds) == 7 + 32  # "sha256:" + 32 hex chars

    def test_different_content_different_digest(self):
        assert content_digest(b"a") != content_digest(b"b")


class TestEmbedExtract:
    """Tests for embed/extract signature helpers."""

    def test_embed_and_extract(self):
        bundle = {"name": "test-pack", "version": "1.0", "iocs": []}
        sig = SignatureBundle(
            signer_identity="alice@example.com",
            provider="sigstore",
            raw_signature="sigdata==",
            digest="abc",
        )
        embedded = embed_signature(bundle, sig)
        assert "_crypto" in embedded
        assert embedded["name"] == "test-pack"
        assert embedded["_crypto"]["provider"] == "sigstore"

        extracted_content, extracted_sig = extract_signature(embedded)
        assert "_crypto" not in extracted_content
        assert extracted_sig is not None
        assert extracted_sig.provider == "sigstore"

    def test_extract_without_signature(self):
        bundle = {"name": "test"}
        content, sig = extract_signature(dict(bundle))
        assert content == bundle
        assert sig is None


class TestDetachedSignatureIO:
    """Tests for writing and reading .sig files."""

    def test_write_and_read_roundtrip(self):
        sig = SignatureBundle(
            signer_identity="test@example.com",
            provider="sigstore",
            raw_signature="base64data==",
            digest="abc123",
        )
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            bundle_path = Path(tf.name)

        try:
            sig_path = write_detached_signature(sig, bundle_path)
            assert sig_path.exists()
            assert sig_path.name.endswith(".json.sig")

            loaded = read_detached_signature(bundle_path)
            assert loaded is not None
            assert loaded.provider == "sigstore"
            assert loaded.raw_signature == "base64data=="
        finally:
            bundle_path.unlink(missing_ok=True)
            sig_path.unlink(missing_ok=True)

    def test_read_missing_sig(self):
        with tempfile.NamedTemporaryFile(suffix=".json") as tf:
            path = Path(tf.name)
        # File no longer exists after context manager
        result = read_detached_signature(path)
        assert result is None


class TestSignVerifyIntegration:
    """Integration tests for sign/verify flow (mocked)."""

    def test_verify_unsigned_returns_true(self):
        """Unsigned bundles should be rejected (fail-closed default)."""
        sb = SignatureBundle.unsigned(digest="sha256:abc")
        result = verify_content(b"any content", sb)
        assert result is False

    def test_sign_content_unknown_method_raises(self):
        with pytest.raises(ValueError, match="Unknown signing method"):
            sign_content(b"test", method="unknown")

    @patch("picosentry.scan.crypto._check_sigstore")
    def test_sign_content_sigstore_not_installed(self, mock_check):
        mock_check.return_value = False
        with pytest.raises(ImportError, match="sigstore"):
            sign_content(b"test", method="sigstore")


class TestSignatureBundleJSON:
    """Ensure SignatureBundle serializes/deserializes cleanly to JSON."""

    def test_json_roundtrip(self):
        sb = SignatureBundle(
            signer_identity="ci@github.com",
            provider="sigstore",
            raw_signature="eyJhbGci...",
            certificate="-----BEGIN CERTIFICATE-----",
            digest="abcdef1234567890",
            signed_at="2026-05-21T12:00:00Z",
        )
        json_str = json.dumps(sb.to_dict())
        data = json.loads(json_str)
        sb2 = SignatureBundle.from_dict(data)
        assert sb2.signer_identity == sb.signer_identity
        assert sb2.provider == sb.provider
        assert sb2.digest == sb.digest
        assert sb2.signed_at == sb.signed_at