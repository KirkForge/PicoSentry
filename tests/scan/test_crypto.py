"""Tests for cryptographic signing and verification of bundles."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

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


def _has_sigstore() -> bool:
    return importlib.util.find_spec("sigstore") is not None


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


class TestSigstoreSigning:
    """Mocked tests for the sigstore 4.x signing path."""

    pytestmark = pytest.mark.skipif(not _has_sigstore(), reason="sigstore extra not installed")

    @patch("picosentry.scan.crypto._check_sigstore")
    @patch("sigstore.models.ClientTrustConfig")
    @patch("sigstore.sign.SigningContext")
    @patch("sigstore.oidc.IdentityToken")
    def test_sign_content_sigstore_with_env_token(self, mock_token_cls, mock_sign_ctx, mock_trust_config, mock_check):
        mock_check.return_value = True

        token_obj = MagicMock()
        token_obj.identity = "ci@example.com"
        mock_token_cls.return_value = token_obj

        signer = MagicMock()
        bundle = MagicMock()
        bundle.to_json.return_value = '{"mock": "bundle"}'
        signer.sign_artifact.return_value = bundle
        signer.__enter__ = MagicMock(return_value=signer)
        signer.__exit__ = MagicMock(return_value=False)
        signing_ctx = MagicMock()
        signing_ctx.signer.return_value = signer
        mock_sign_ctx.from_trust_config.return_value = signing_ctx

        with patch.dict(os.environ, {"SIGSTORE_IDENTITY_TOKEN": "fake.jwt.token"}, clear=False):
            result = sign_content(b"hello", method="sigstore")

        assert result.provider == "sigstore"
        assert result.signer_identity == "ci@example.com"
        assert result.raw_signature == '{"mock": "bundle"}'
        mock_token_cls.assert_called_once_with("fake.jwt.token")
        signer.sign_artifact.assert_called_once_with(b"hello")

    @patch("picosentry.scan.crypto._check_sigstore")
    @patch("sigstore.models.ClientTrustConfig")
    @patch("sigstore.sign.SigningContext")
    @patch("sigstore.oidc.Issuer")
    def test_sign_content_sigstore_interactive_issuer(
        self,
        mock_issuer_cls: MagicMock,
        mock_sign_ctx: MagicMock,
        mock_trust_config: MagicMock,
        mock_check: MagicMock,
    ) -> None:
        mock_check.return_value = True

        token_obj = MagicMock()
        token_obj.identity = "dev@example.com"
        issuer = MagicMock()
        issuer.identity_token.return_value = token_obj
        mock_issuer_cls.return_value = issuer

        signer = MagicMock()
        bundle = MagicMock()
        bundle.to_json.return_value = '{"mock": "bundle"}'
        signer.sign_artifact.return_value = bundle
        signer.__enter__ = MagicMock(return_value=signer)
        signer.__exit__ = MagicMock(return_value=False)
        signing_ctx = MagicMock()
        signing_ctx.signer.return_value = signer
        mock_sign_ctx.from_trust_config.return_value = signing_ctx

        trust_config = MagicMock()
        trust_config.signing_config.get_oidc_url.return_value = "https://accounts.google.com"
        mock_trust_config.production.return_value = trust_config

        env = os.environ.copy()
        env.pop("SIGSTORE_IDENTITY_TOKEN", None)
        with patch.dict(os.environ, env, clear=True):
            result = sign_content(b"hello", method="sigstore")

        assert result.provider == "sigstore"
        assert result.signer_identity == "dev@example.com"
        mock_issuer_cls.assert_called_once_with("https://accounts.google.com")


class TestSigstoreVerification:
    """Mocked tests for the sigstore 4.x verification path."""

    pytestmark = pytest.mark.skipif(not _has_sigstore(), reason="sigstore extra not installed")

    @patch("picosentry.scan.crypto._check_sigstore")
    @patch("sigstore.models.Bundle")
    @patch("sigstore.verify.Verifier")
    def test_verify_content_sigstore_success(self, mock_verifier_cls, mock_bundle_cls, mock_check):
        mock_check.return_value = True
        mock_bundle_cls.from_json.return_value = MagicMock()
        verifier = MagicMock()
        mock_verifier_cls.production.return_value = verifier

        sb = SignatureBundle(
            signer_identity="ci@example.com",
            provider="sigstore",
            raw_signature='{"mock": "bundle"}',
            digest="abc",
        )
        assert verify_content(b"hello", sb) is True
        verifier.verify_artifact.assert_called_once()

    @patch("picosentry.scan.crypto._check_sigstore")
    @patch("sigstore.models.Bundle")
    @patch("sigstore.verify.Verifier")
    def test_verify_content_sigstore_failure(self, mock_verifier_cls, mock_bundle_cls, mock_check):
        from sigstore.errors import VerificationError

        mock_check.return_value = True
        mock_bundle_cls.from_json.return_value = MagicMock()
        verifier = MagicMock()
        verifier.verify_artifact.side_effect = VerificationError("bad signature")
        mock_verifier_cls.production.return_value = verifier

        sb = SignatureBundle(
            signer_identity="ci@example.com",
            provider="sigstore",
            raw_signature='{"mock": "bundle"}',
            digest="abc",
        )
        assert verify_content(b"hello", sb) is False


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
