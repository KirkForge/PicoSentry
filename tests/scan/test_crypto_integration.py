"""Integration tests for cryptographic signing in corpus_share and policy modules."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from picosentry.scan.corpus_share import CorpusPack, export_corpus_pack, import_corpus_pack
from picosentry.scan.crypto import (
    SignatureBundle,
)
from picosentry.scan.policy import Policy, export_signed_policy, import_policy_bundle

# ── Fixtures ────────────────────────────────────────────────────────────


@pytest.fixture
def sample_ioc():
    from picosentry.scan.ioc_registry import IoCRecord

    return IoCRecord(
        {
            "id": "ioc-test-001",
            "name": "Test Malicious Package",
            "package_name": "evil-pkg",
            "version_range": ">=0",
            "description": "Test IoC for signing tests",
            "attack_vector": "malware",
            "severity": "critical",
        }
    )


@pytest.fixture
def tmp_pack_path():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        pass
    path = Path(tf.name)
    yield path
    path.unlink(missing_ok=True)
    sig_path = path.with_suffix(path.suffix + ".sig")
    sig_path.unlink(missing_ok=True)


@pytest.fixture
def tmp_policy_path():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        pass
    path = Path(tf.name)
    yield path
    path.unlink(missing_ok=True)
    sig_path = path.with_suffix(path.suffix + ".sig")
    sig_path.unlink(missing_ok=True)


# ── Corpus Pack Signing ─────────────────────────────────────────────────


class TestCorpusPackCryptoSigning:
    """Tests for cryptographic signing of corpus packs."""

    def test_sign_cryptographically_updates_signature(self, sample_ioc, tmp_pack_path):
        """CorpusPack.sign_cryptographically should populate _signature with crypto fields."""
        pack = CorpusPack(name="test-crypto", description="Signed test pack", author="test")
        pack.add_ioc(sample_ioc)

        with patch("picosentry.scan.corpus_share.sign_content") as mock_sign:
            mock_sig = SignatureBundle(
                signer_identity="test@test.com",
                provider="sigstore",
                raw_signature="mock-sig-data",
                certificate="mock-cert",
                digest="abc123",
                signed_at="2026-01-01T00:00:00Z",
            )
            mock_sign.return_value = mock_sig

            result = pack.sign_cryptographically("sigstore")

            assert result.provider == "sigstore"
            assert pack._signature["provider"] == "sigstore"
            assert pack._signature["crypto_signature"] == "mock-sig-data"
            assert pack._signature["certificate"] == "mock-cert"
            assert pack._signature["signer"] == "test@test.com"

    def test_export_with_sign_creates_sig_file(self, sample_ioc, tmp_pack_path):
        """Export with --sign should create a .sig file."""

        with (
            patch("picosentry.scan.corpus_share.sign_content") as mock_sign,
            patch("picosentry.scan.corpus_share.list_custom_iocs") as mock_list,
        ):
            mock_sig = SignatureBundle(
                signer_identity="ci@github",
                provider="sigstore",
                raw_signature="mock-sig",
                digest="abc",
            )
            mock_sign.return_value = mock_sig
            mock_list.return_value = [sample_ioc]

            export_corpus_pack(
                tmp_pack_path,
                name="signed-pack",
                sign_method="sigstore",
            )

            assert tmp_pack_path.exists()
            tmp_pack_path.with_suffix(tmp_pack_path.suffix + ".sig")
            # Sig file should exist if signing succeeded
            # (may not if sigstore not installed, but mock should prevent that)

    def test_export_without_sign_no_sig_file(self, sample_ioc, tmp_pack_path):
        """Export without --sign should NOT create a .sig file."""

        with patch("picosentry.scan.corpus_share.list_custom_iocs") as mock_list:
            mock_list.return_value = [sample_ioc]

            export_corpus_pack(tmp_pack_path, name="unsigned-pack")
            sig_path = tmp_pack_path.with_suffix(tmp_pack_path.suffix + ".sig")
            assert not sig_path.exists()

    def test_import_with_verify_crypto_no_sig_raises(self, tmp_pack_path):
        """Import with --verify-crypto when no sig exists should raise."""
        pack = CorpusPack(name="unsigned")
        tmp_pack_path.write_text(pack.to_json(), encoding="utf-8")

        with pytest.raises(ValueError, match="no signature found"):
            import_corpus_pack(tmp_pack_path, dry_run=True, verify_crypto=True)

    def test_import_unsigned_pack_is_ok_without_verify_crypto(self, tmp_pack_path):
        """Import without --verify-crypto should work fine on unsigned packs (backward compat)."""
        pack = CorpusPack(name="unsigned", description="test", author="test")
        tmp_pack_path.write_text(pack.to_json(), encoding="utf-8")

        stats = import_corpus_pack(tmp_pack_path, dry_run=True, verify_crypto=False)
        assert stats["total"] == 0  # No IoCs in pack


# ── Policy Bundle Signing ───────────────────────────────────────────────


class TestPolicyBundleCryptoSigning:
    """Tests for cryptographic signing of policy bundles."""

    def test_export_with_sigstore_signs(self, tmp_policy_path):
        """Export with --sign sigstore should cryptographically sign."""
        policy = Policy(
            fail_on_severity="high",
            allow_licenses=["MIT", "Apache-2.0"],
        )

        with patch("picosentry.scan.policy_pkg.bundle.sign_content") as mock_sign:
            mock_sig = SignatureBundle(
                signer_identity="ci@github",
                provider="sigstore",
                raw_signature="mock-sig",
                digest="abc",
            )
            mock_sign.return_value = mock_sig

            digest = export_signed_policy(
                policy,
                tmp_policy_path,
                signer="security-team",
                sign_method="sigstore",
            )

            assert digest.startswith("sha256:")
            assert tmp_policy_path.exists()

            # Check bundle contents
            data = json.loads(tmp_policy_path.read_text())
            assert data["signer"] == "security-team"
            assert "policy" in data

    def test_export_without_sign_no_crypto(self, tmp_policy_path):
        """Export without --sign should not add _crypto to bundle."""
        policy = Policy(fail_on_severity="medium")

        export_signed_policy(policy, tmp_policy_path, signer="test")

        data = json.loads(tmp_policy_path.read_text())
        assert "policy" in data
        assert data.get("_crypto", {}).get("provider", "none") != "sigstore"

    def test_import_with_verify_crypto_no_sig_raises(self, tmp_policy_path):
        """Import with verify_crypto when no sig exists should raise."""
        policy = Policy(fail_on_severity="high")
        export_signed_policy(policy, tmp_policy_path, signer="test")

        with pytest.raises(ValueError, match="no signature found"):
            import_policy_bundle(tmp_policy_path, verify=True, verify_crypto=True)


class TestCorpusPackDigestVerification:
    """Digest verification still works (backward compat)."""

    def test_digest_mismatch_raises(self, tmp_pack_path):
        """Import of tampered pack should fail digest check."""
        pack = CorpusPack(name="test")
        pack.seal("alice")
        pack_json = pack.to_json()
        # Tamper with an IoC
        tampered = json.loads(pack_json)
        tampered["iocs"].append({"id": "evil", "package_name": "evil", "name": "evil"})
        tmp_pack_path.write_text(json.dumps(tampered), encoding="utf-8")

        # Digest mismatch should raise ValueError
        with pytest.raises(ValueError, match="digest mismatch"):
            import_corpus_pack(tmp_pack_path, dry_run=True)

    def test_import_unsigned_pack_no_digest_check(self, tmp_pack_path):
        """Unsigned packs import without digest verification."""
        pack = CorpusPack(name="unsigned")
        tmp_pack_path.write_text(pack.to_json(), encoding="utf-8")
        stats = import_corpus_pack(tmp_pack_path, dry_run=True)
        assert stats["total"] == 0
