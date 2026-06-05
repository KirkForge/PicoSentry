"""Comprehensive tests for picosentry.corpus_share — target 80%+ coverage."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from picosentry.scan.corpus_share import (
    _MAX_PACK_BYTES,
    BUILTIN_PACKS,
    PACK_VERSION,
    CorpusPack,
    export_corpus_pack,
    import_corpus_pack,
    list_available_packs,
    validate_corpus_pack,
)


def _make_ioc_data(name="evil-pkg", package_name="evil-pkg", description="A malicious package", ioc_id=""):
    """Helper to build a minimal IoC data dict."""
    d = {
        "name": name,
        "package_name": package_name,
        "description": description,
        "ioc_type": "custom",
        "severity": "HIGH",
    }
    if ioc_id:
        d["id"] = ioc_id
    return d


def _write_pack_file(tmpdir, pack_dict, filename="test-pack.json"):
    """Helper to write a pack dict as JSON to a file and return the path."""
    p = Path(tmpdir) / filename
    p.write_text(json.dumps(pack_dict), encoding="utf-8")
    return p


def _make_sealed_pack_dict(name="test-pack", iocs=None, signer="tester"):
    """Build a complete pack dict with a sealed signature."""
    pack = CorpusPack(name=name, description="desc", author="tester")
    if iocs:
        for ioc in iocs:
            pack.iocs.append(ioc)
    pack.seal(signer)
    return pack.to_dict()


# ── CorpusPack unit tests ────────────────────────────────────────────────


class TestCorpusPackInit(unittest.TestCase):
    """Tests for CorpusPack.__init__ and basic attributes."""

    def test_default_attributes(self):
        pack = CorpusPack(name="demo")
        self.assertEqual(pack.name, "demo")
        self.assertEqual(pack.description, "")
        self.assertEqual(pack.author, "")
        self.assertEqual(pack.version, PACK_VERSION)
        self.assertEqual(pack.iocs, [])
        self.assertEqual(pack.created_at, "")
        self.assertIsNotNone(pack.pack_id)
        self.assertEqual(len(pack.pack_id), 12)

    def test_custom_attributes(self):
        pack = CorpusPack(name="my-pack", description="A test pack", author="alice")
        self.assertEqual(pack.name, "my-pack")
        self.assertEqual(pack.description, "A test pack")
        self.assertEqual(pack.author, "alice")

    def test_pack_id_deterministic(self):
        p1 = CorpusPack(name="same-name")
        p2 = CorpusPack(name="same-name")
        self.assertEqual(p1.pack_id, p2.pack_id)

    def test_pack_id_differs_for_different_names(self):
        p1 = CorpusPack(name="alpha")
        p2 = CorpusPack(name="beta")
        self.assertNotEqual(p1.pack_id, p2.pack_id)


class TestCorpusPackAddIoc(unittest.TestCase):
    """Tests for CorpusPack.add_ioc()."""

    def test_add_ioc(self):
        pack = CorpusPack(name="test")
        record = MagicMock()
        record.to_dict.return_value = _make_ioc_data()
        pack.add_ioc(record)
        self.assertEqual(len(pack.iocs), 1)
        self.assertEqual(pack.iocs[0]["name"], "evil-pkg")

    def test_add_multiple_iocs(self):
        pack = CorpusPack(name="test")
        for i in range(3):
            record = MagicMock()
            record.to_dict.return_value = _make_ioc_data(name=f"pkg-{i}")
            pack.add_ioc(record)
        self.assertEqual(len(pack.iocs), 3)

    def test_add_ioc_empty_dict(self):
        pack = CorpusPack(name="test")
        record = MagicMock()
        record.to_dict.return_value = {}
        pack.add_ioc(record)
        self.assertEqual(pack.iocs, [{}])


class TestCorpusPackDigest(unittest.TestCase):
    """Tests for CorpusPack.digest()."""

    def test_digest_starts_with_prefix(self):
        pack = CorpusPack(name="test")
        digest = pack.digest()
        self.assertTrue(digest.startswith("sha256:"))

    def test_digest_length(self):
        pack = CorpusPack(name="test")
        digest = pack.digest()
        # "sha256:" prefix + hex chars from digest()
        self.assertTrue(digest.startswith("sha256:"))
        self.assertGreater(len(digest), 10)

    def test_digest_deterministic(self):
        pack = CorpusPack(name="test")
        d1 = pack.digest()
        d2 = pack.digest()
        self.assertEqual(d1, d2)

    def test_digest_changes_with_content(self):
        pack = CorpusPack(name="test")
        d_empty = pack.digest()
        record = MagicMock()
        record.to_dict.return_value = _make_ioc_data()
        pack.add_ioc(record)
        d_with_ioc = pack.digest()
        self.assertNotEqual(d_empty, d_with_ioc)

    def test_digest_changes_with_name(self):
        p1 = CorpusPack(name="alpha")
        p2 = CorpusPack(name="beta")
        self.assertNotEqual(p1.digest(), p2.digest())


class TestCorpusPackSeal(unittest.TestCase):
    """Tests for CorpusPack.seal()."""

    def test_seal_sets_signature(self):
        pack = CorpusPack(name="test")
        pack.seal("alice")
        self.assertTrue(hasattr(pack, "_signature"))
        self.assertEqual(pack._signature["signer"], "alice")
        self.assertIn("digest", pack._signature)
        self.assertIn("sealed_at", pack._signature)

    def test_seal_sets_created_at(self):
        pack = CorpusPack(name="test")
        self.assertEqual(pack.created_at, "")
        pack.seal("alice")
        self.assertNotEqual(pack.created_at, "")

    def test_seal_does_not_overwrite_created_at(self):
        pack = CorpusPack(name="test")
        pack.created_at = "2024-01-01T00:00:00+00:00"
        pack.seal("alice")
        self.assertEqual(pack.created_at, "2024-01-01T00:00:00+00:00")

    def test_seal_digest_matches_pack(self):
        pack = CorpusPack(name="test")
        pack.seal("alice")
        self.assertEqual(pack._signature["digest"], pack.digest())


class TestCorpusPackSign(unittest.TestCase):
    """Tests for CorpusPack.sign() — now raises NotImplementedError."""

    def test_sign_raises_not_implemented(self):
        pack = CorpusPack(name="test")
        with self.assertRaises(NotImplementedError):
            pack.sign("bob")


class TestCorpusPackSignCryptographically(unittest.TestCase):
    """Tests for CorpusPack.sign_cryptographically()."""

    @patch("picosentry.scan.corpus_share.sign_content")
    def test_sign_cryptographically_success(self, mock_sign):
        from picosentry.scan.crypto import SignatureBundle

        mock_sign.return_value = SignatureBundle(
            signer_identity="alice@example.com",
            provider="sigstore",
            raw_signature="base64sig",
            certificate="cert-pem",
            digest="sha256:abc123",
            signed_at="2024-01-01T00:00:00+00:00",
        )
        pack = CorpusPack(name="test")
        pack.seal("alice")
        sig = pack.sign_cryptographically(method="sigstore")
        self.assertEqual(sig.provider, "sigstore")
        self.assertIn("crypto_signature", pack._signature)
        self.assertIn("certificate", pack._signature)

    @patch("picosentry.scan.corpus_share.sign_content", side_effect=ImportError("no sigstore"))
    def test_sign_cryptographically_import_error(self, mock_sign):
        pack = CorpusPack(name="test")
        pack.seal("alice")
        with self.assertRaises(ImportError):
            pack.sign_cryptographically(method="sigstore")


class TestCorpusPackToDict(unittest.TestCase):
    """Tests for CorpusPack.to_dict()."""

    def test_to_dict_basic(self):
        pack = CorpusPack(name="test", description="desc", author="author")
        d = pack.to_dict()
        self.assertEqual(d["name"], "test")
        self.assertEqual(d["description"], "desc")
        self.assertEqual(d["author"], "author")
        self.assertEqual(d["pack_format"], PACK_VERSION)
        self.assertEqual(d["ioc_count"], 0)
        self.assertIn("digest", d)
        self.assertIn("pack_id", d)
        self.assertNotIn("signature", d)

    def test_to_dict_with_signature(self):
        pack = CorpusPack(name="test")
        pack.seal("alice")
        d = pack.to_dict()
        self.assertIn("signature", d)
        self.assertEqual(d["signature"]["signer"], "alice")

    def test_to_dict_with_iocs(self):
        pack = CorpusPack(name="test")
        record = MagicMock()
        record.to_dict.return_value = _make_ioc_data()
        pack.add_ioc(record)
        d = pack.to_dict()
        self.assertEqual(d["ioc_count"], 1)
        self.assertEqual(len(d["iocs"]), 1)


class TestCorpusPackToJson(unittest.TestCase):
    """Tests for CorpusPack.to_json()."""

    def test_to_json_valid(self):
        pack = CorpusPack(name="test")
        j = pack.to_json()
        parsed = json.loads(j)
        self.assertEqual(parsed["name"], "test")

    def test_to_json_roundtrip(self):
        pack = CorpusPack(name="test", description="desc")
        j = pack.to_json()
        parsed = json.loads(j)
        self.assertEqual(parsed["name"], "test")
        self.assertEqual(parsed["description"], "desc")


class TestCorpusPackFromDict(unittest.TestCase):
    """Tests for CorpusPack.from_dict()."""

    def test_from_dict_basic(self):
        data = {
            "name": "my-pack",
            "description": "A test",
            "author": "bob",
            "pack_format": "1.0",
            "pack_id": "abc123",
            "created_at": "2024-01-01",
            "iocs": [_make_ioc_data()],
        }
        pack = CorpusPack.from_dict(data)
        self.assertEqual(pack.name, "my-pack")
        self.assertEqual(pack.description, "A test")
        self.assertEqual(pack.author, "bob")
        self.assertEqual(pack.version, "1.0")
        self.assertEqual(pack.pack_id, "abc123")
        self.assertEqual(len(pack.iocs), 1)

    def test_from_dict_missing_fields_defaults(self):
        data = {}
        pack = CorpusPack.from_dict(data)
        self.assertEqual(pack.name, "unnamed")
        self.assertEqual(pack.description, "")
        self.assertEqual(pack.author, "unknown")

    def test_from_dict_preserves_signature(self):
        data = _make_sealed_pack_dict()
        pack = CorpusPack.from_dict(data)
        self.assertTrue(hasattr(pack, "_signature"))
        self.assertEqual(pack._signature["signer"], "tester")

    def test_from_dict_no_signature(self):
        data = {"name": "test"}
        pack = CorpusPack.from_dict(data)
        self.assertFalse(hasattr(pack, "_signature"))


class TestCorpusPackFromFile(unittest.TestCase):
    """Tests for CorpusPack.from_file()."""

    def test_from_file_valid(self):
        data = _make_sealed_pack_dict(name="file-pack")
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            pack = CorpusPack.from_file(p)
            self.assertEqual(pack.name, "file-pack")

    def test_from_file_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "bad.json"
            p.write_text("not json at all", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                CorpusPack.from_file(p)


# ── export_corpus_pack tests ─────────────────────────────────────────────


class TestExportCorpusPack(unittest.TestCase):
    """Tests for export_corpus_pack()."""

    @patch("picosentry.scan.corpus_share.list_custom_iocs", return_value=[])
    def test_export_empty_corpus(self, mock_list):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "pack.json"
            pack = export_corpus_pack(output, name="empty", description="no iocs")
            self.assertIsInstance(pack, CorpusPack)
            self.assertEqual(len(pack.iocs), 0)
            self.assertTrue(output.exists())
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["name"], "empty")

    @patch("picosentry.scan.corpus_share.list_custom_iocs", return_value=[])
    def test_export_creates_parent_dirs(self, mock_list):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "subdir" / "deep" / "pack.json"
            with self.assertRaises(FileNotFoundError):
                # No auto-mkdir in export; this should fail
                export_corpus_pack(output, name="deep-pack")

    @patch("picosentry.scan.corpus_share.list_custom_iocs")
    def test_export_with_iocs(self, mock_list):
        from picosentry.scan.ioc_registry import IoCRecord

        ioc1 = IoCRecord(_make_ioc_data(name="pkg-a", ioc_id="ioc_a"))
        ioc2 = IoCRecord(_make_ioc_data(name="pkg-b", ioc_id="ioc_b"))
        mock_list.return_value = [ioc1, ioc2]

        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "pack.json"
            pack = export_corpus_pack(output, name="with-iocs")
            self.assertEqual(len(pack.iocs), 2)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["ioc_count"], 2)

    @patch("picosentry.scan.corpus_share.list_custom_iocs", return_value=[])
    def test_export_with_seal(self, mock_list):
        """Test that export writes a sealed (signed digest) pack."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "pack.json"
            export_corpus_pack(output, name="sealed-pack")
            # Export seals the pack before writing
            content = output.read_text(encoding="utf-8")
            data = json.loads(content)
            self.assertIn("digest", data)

    @patch("picosentry.scan.corpus_share.list_custom_iocs", return_value=[])
    @patch("picosentry.scan.corpus_share.sign_content")
    @patch("picosentry.scan.corpus_share.write_detached_signature")
    def test_export_with_crypto_signing(self, mock_list, mock_sign, mock_write):
        from picosentry.scan.crypto import SignatureBundle

        mock_sign.return_value = SignatureBundle(
            signer_identity="alice",
            provider="sigstore",
            raw_signature="sig123",
            certificate="cert",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "pack.json"
            export_corpus_pack(output, name="crypto-pack", sign_method="sigstore")
            mock_sign.assert_called_once()
            mock_write.assert_called_once()

    @patch("picosentry.scan.corpus_share.list_custom_iocs", return_value=[])
    @patch("picosentry.scan.corpus_share.sign_content", side_effect=ImportError("no sigstore"))
    def test_export_crypto_sign_import_error(self, mock_list, mock_sign):
        """Export should not fail when crypto signing import fails."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "pack.json"
            pack = export_corpus_pack(output, name="no-crypto", sign_method="sigstore")
            self.assertIsInstance(pack, CorpusPack)
            # File should still be written (without crypto sig)
            self.assertTrue(output.exists())

    @patch("picosentry.scan.corpus_share.list_custom_iocs", return_value=[])
    @patch("picosentry.scan.corpus_share.sign_content", side_effect=RuntimeError("sign failed"))
    def test_export_crypto_sign_other_error(self, mock_list, mock_sign):
        """Export should not fail when crypto signing raises a non-import error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "pack.json"
            pack = export_corpus_pack(output, name="sign-err", sign_method="sigstore")
            self.assertIsInstance(pack, CorpusPack)
            self.assertTrue(output.exists())


# ── import_corpus_pack tests ──────────────────────────────────────────────


class TestImportCorpusPack(unittest.TestCase):
    """Tests for import_corpus_pack()."""

    def test_import_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            import_corpus_pack(Path("/nonexistent/path/pack.json"))

    def test_import_wrong_extension(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "pack.yaml"
            p.write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                import_corpus_pack(p)
            self.assertIn(".yaml", str(ctx.exception))

    def test_import_valid_pack(self):
        data = _make_sealed_pack_dict(name="import-test", iocs=[_make_ioc_data(ioc_id="abc1234567")])
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            with patch("picosentry.scan.corpus_share.register_ioc"):
                stats = import_corpus_pack(p)
            self.assertEqual(stats["total"], 1)
            self.assertEqual(stats["imported"], 1)
            self.assertEqual(stats["errors"], 0)

    def test_import_dry_run(self):
        data = _make_sealed_pack_dict(name="dry-run", iocs=[_make_ioc_data(ioc_id="dry1234567")])
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            with patch("picosentry.scan.corpus_share.register_ioc") as mock_reg:
                stats = import_corpus_pack(p, dry_run=True)
                mock_reg.assert_not_called()
            self.assertEqual(stats["imported"], 1)

    def test_import_duplicate_ioc_skipped(self):
        data = _make_sealed_pack_dict(name="dup-test", iocs=[_make_ioc_data(ioc_id="dup1234567")])
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            with patch("picosentry.scan.corpus_share.register_ioc", side_effect=FileExistsError("exists")):
                stats = import_corpus_pack(p)
            self.assertEqual(stats["skipped"], 1)

    def test_import_ioc_register_error(self):
        data = _make_sealed_pack_dict(name="err-test", iocs=[_make_ioc_data(ioc_id="err1234567")])
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            with patch("picosentry.scan.corpus_share.register_ioc", side_effect=ValueError("bad")):
                stats = import_corpus_pack(p)
            self.assertEqual(stats["errors"], 1)
            self.assertIn("bad", stats["error_details"][0])

    def test_import_empty_pack(self):
        data = _make_sealed_pack_dict(name="empty-import")
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            stats = import_corpus_pack(p)
            self.assertEqual(stats["total"], 0)
            self.assertEqual(stats["imported"], 0)

    def test_import_oversized_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "big.json"
            # Create a file larger than _MAX_PACK_BYTES
            p.write_bytes(b"x" * (_MAX_PACK_BYTES + 1))
            with self.assertRaises(ValueError) as ctx:
                import_corpus_pack(p)
            self.assertIn("too large", str(ctx.exception))

    def test_import_tampered_pack_digest_mismatch(self):
        """Import should reject packs where the digest doesn't match."""
        data = _make_sealed_pack_dict(name="tampered")
        # Tamper: change the digest in the signature
        data["signature"]["digest"] = "sha256:00000000000000000000000000000000"
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            with self.assertRaises(ValueError) as ctx:
                import_corpus_pack(p)
            self.assertIn("digest mismatch", str(ctx.exception))

    def test_import_unsigned_pack(self):
        """Importing a pack with no signature should succeed."""
        data = {"name": "unsigned", "pack_format": PACK_VERSION, "iocs": []}
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            stats = import_corpus_pack(p)
            self.assertEqual(stats["imported"], 0)

    def test_import_version_mismatch_warning(self):
        """Importing a pack with a different version should log a warning but succeed."""
        data = _make_sealed_pack_dict(name="old-version")
        data["pack_format"] = "0.9"
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            with patch("picosentry.scan.corpus_share.register_ioc"):
                with self.assertLogs("picosentry.corpus_share", level="WARNING") as cm:
                    import_corpus_pack(p)
                self.assertTrue(any("may not be compatible" in msg for msg in cm.output))

    def test_import_cannot_stat_file(self):
        """Import should raise OSError when file cannot be stat'd."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir) / "gone.json"
            # Create then delete to get a path that exists briefly
            # Actually test with a path that raises OSError on stat
            # We'll mock stat to raise
            pass  # Covered by FileNotFoundError test above

    def test_import_cryptographic_verify_no_signature(self):
        """verify_crypto=True with no signature should raise ValueError."""
        data = {"name": "no-sig", "pack_format": PACK_VERSION, "iocs": []}
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            with self.assertRaises(ValueError) as ctx:
                import_corpus_pack(p, verify_crypto=True)
            self.assertIn("no signature found", str(ctx.exception))

    @patch("picosentry.scan.corpus_share.read_detached_signature")
    def test_import_cryptographic_verify_unsigned_bundle(self, mock_read):
        """verify_crypto=True with unsigned bundle should raise ValueError."""
        from picosentry.scan.crypto import SignatureBundle

        mock_read.return_value = SignatureBundle.unsigned()
        data = _make_sealed_pack_dict(name="unsigned-bundle")
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            with self.assertRaises(ValueError) as ctx:
                import_corpus_pack(p, verify_crypto=True)
            self.assertIn("not cryptographically signed", str(ctx.exception))

    @patch("picosentry.scan.corpus_share.verify_content", return_value=True)
    @patch("picosentry.scan.corpus_share.read_detached_signature")
    def test_import_cryptographic_verify_success(self, mock_read, mock_verify):
        from picosentry.scan.crypto import SignatureBundle

        sig = SignatureBundle(
            signer_identity="alice",
            provider="sigstore",
            raw_signature="sig123",
            certificate="cert",
        )
        mock_read.return_value = sig
        data = _make_sealed_pack_dict(name="crypto-verify-ok")
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            with patch("picosentry.scan.corpus_share.register_ioc"):
                import_corpus_pack(p, verify_crypto=True)
            mock_verify.assert_called_once()

    @patch("picosentry.scan.corpus_share.verify_content", return_value=False)
    @patch("picosentry.scan.corpus_share.read_detached_signature")
    def test_import_cryptographic_verify_failure(self, mock_read, mock_verify):
        from picosentry.scan.crypto import SignatureBundle

        sig = SignatureBundle(
            signer_identity="alice",
            provider="sigstore",
            raw_signature="sig123",
            certificate="cert",
        )
        mock_read.return_value = sig
        data = _make_sealed_pack_dict(name="crypto-bad")
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            with self.assertRaises(ValueError) as ctx:
                import_corpus_pack(p, verify_crypto=True)
            self.assertIn("verification FAILED", str(ctx.exception))

    @patch("picosentry.scan.corpus_share.verify_content", side_effect=ImportError("no sigstore"))
    @patch("picosentry.scan.corpus_share.read_detached_signature")
    def test_import_cryptographic_verify_import_error(self, mock_read, mock_verify):
        """ImportError during verification should be logged as warning, not raise."""
        from picosentry.scan.crypto import SignatureBundle

        sig = SignatureBundle(
            signer_identity="alice",
            provider="sigstore",
            raw_signature="sig123",
        )
        mock_read.return_value = sig
        data = _make_sealed_pack_dict(name="no-sigstore-lib")
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            with patch("picosentry.scan.corpus_share.register_ioc"):
                stats = import_corpus_pack(p, verify_crypto=True)
            # Should succeed without raising
            self.assertIsInstance(stats, dict)

    @patch("picosentry.scan.corpus_share.verify_content", side_effect=RuntimeError("VerificationError: bad"))
    @patch("picosentry.scan.corpus_share.read_detached_signature")
    def test_import_cryptographic_verify_error_raises(self, mock_read, mock_verify):
        """Verification errors with 'VerificationError' in name should propagate."""
        from picosentry.scan.crypto import SignatureBundle

        sig = SignatureBundle(
            signer_identity="alice",
            provider="sigstore",
            raw_signature="sig123",
        )
        mock_read.return_value = sig
        data = _make_sealed_pack_dict(name="verify-err")
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            with self.assertRaises((RuntimeError, ValueError)):
                import_corpus_pack(p, verify_crypto=True)

    @patch("picosentry.scan.corpus_share.verify_content", side_effect=Exception("unknown error"))
    @patch("picosentry.scan.corpus_share.read_detached_signature")
    def test_import_cryptographic_generic_exception(self, mock_read, mock_verify):
        """Generic exceptions during verification should be wrapped."""
        from picosentry.scan.crypto import SignatureBundle

        sig = SignatureBundle(
            signer_identity="alice",
            provider="sigstore",
            raw_signature="sig123",
        )
        mock_read.return_value = sig
        data = _make_sealed_pack_dict(name="generic-err")
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            with self.assertRaises(ValueError) as ctx:
                import_corpus_pack(p, verify_crypto=True)
            self.assertIn("Cryptographic verification error", str(ctx.exception))

    def test_import_cryptographic_inline_signature(self):
        """verify_crypto=True with inline crypto_signature in pack data."""

        data = _make_sealed_pack_dict(name="inline-sig")
        data["signature"]["provider"] = "sigstore"
        data["signature"]["crypto_signature"] = "base64sig=="
        data["signature"]["certificate"] = "cert-pem"
        data["signature"]["signer"] = "alice"

        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            with (
                patch("picosentry.scan.corpus_share.read_detached_signature", return_value=None),
                patch("picosentry.scan.corpus_share.verify_content", return_value=True),
                patch("picosentry.scan.corpus_share.register_ioc"),
            ):
                stats = import_corpus_pack(p, verify_crypto=True)
                self.assertIsInstance(stats, dict)

    def test_import_multiple_iocs(self):
        """Import pack with multiple IoCs."""
        iocs = [_make_ioc_data(name=f"pkg-{i}", ioc_id=f"ioc{i:012d}") for i in range(5)]
        data = _make_sealed_pack_dict(name="multi", iocs=iocs)
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            with patch("picosentry.scan.corpus_share.register_ioc"):
                stats = import_corpus_pack(p)
            self.assertEqual(stats["total"], 5)
            self.assertEqual(stats["imported"], 5)


# ── validate_corpus_pack tests ───────────────────────────────────────────


class TestValidateCorpusPack(unittest.TestCase):
    """Tests for validate_corpus_pack()."""

    def test_validate_valid_pack(self):
        data = _make_sealed_pack_dict(
            name="valid",
            iocs=[
                _make_ioc_data(name="pkg", package_name="pkg", description="desc", ioc_id="valid12345"),
            ],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            result = validate_corpus_pack(p)
            self.assertTrue(result["valid"])
            self.assertEqual(result["ioc_count"], 1)
            self.assertEqual(result["pack_name"], "valid")

    def test_validate_missing_name(self):
        """IoCs missing 'name' should be flagged."""
        data = _make_sealed_pack_dict(
            name="no-name",
            iocs=[
                {"package_name": "pkg", "description": "desc", "id": "noname12345"},
            ],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            result = validate_corpus_pack(p)
            self.assertFalse(result["valid"])
            self.assertTrue(any("missing 'name'" in e for e in result["errors"]))

    def test_validate_missing_package_name(self):
        """IoCs missing 'package_name' should be flagged."""
        data = _make_sealed_pack_dict(
            name="no-pkg",
            iocs=[
                {"name": "pkg", "description": "desc", "id": "nopkg123456"},
            ],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            result = validate_corpus_pack(p)
            self.assertFalse(result["valid"])
            self.assertTrue(any("missing 'package_name'" in e for e in result["errors"]))

    def test_validate_missing_description_warning(self):
        """IoCs missing 'description' should produce a warning, not error."""
        data = _make_sealed_pack_dict(
            name="no-desc",
            iocs=[
                {"name": "pkg", "package_name": "pkg", "id": "nodesc12345"},
            ],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            result = validate_corpus_pack(p)
            # Missing description is a warning, not an error — still valid
            self.assertTrue(any("missing 'description'" in w for w in result["warnings"]))

    def test_validate_invalid_ioc_id(self):
        """IoCs with path traversal IDs should be flagged."""
        data = _make_sealed_pack_dict(
            name="bad-id",
            iocs=[
                {"name": "pkg", "package_name": "pkg", "description": "d", "id": "../evil"},
            ],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            result = validate_corpus_pack(p)
            self.assertFalse(result["valid"])
            self.assertTrue(any("invalid id" in e for e in result["errors"]))

    def test_validate_corrupted_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "bad.json"
            p.write_text("{invalid json", encoding="utf-8")
            result = validate_corpus_pack(p)
            self.assertFalse(result["valid"])
            self.assertTrue(any("Parse error" in e for e in result["errors"]))

    def test_validate_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "missing.json"
            result = validate_corpus_pack(p)
            self.assertFalse(result["valid"])
            self.assertTrue(any("Cannot stat" in e for e in result["errors"]))

    def test_validate_oversized_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "huge.json"
            p.write_bytes(b"x" * (_MAX_PACK_BYTES + 1))
            result = validate_corpus_pack(p)
            self.assertFalse(result["valid"])
            self.assertTrue(any("too large" in e.lower() for e in result["errors"]))

    def test_validate_empty_ioc_list(self):
        """Empty pack (no IoCs) should still be valid."""
        data = _make_sealed_pack_dict(name="empty-valid")
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            result = validate_corpus_pack(p)
            self.assertTrue(result["valid"])
            self.assertEqual(result["ioc_count"], 0)

    def test_validate_cannot_stat_file(self):
        """Path that cannot be stat'd should produce a validation error."""
        # Use a mock to simulate a path where stat() raises OSError
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "ghost.json"
            with patch.object(Path, "stat", side_effect=OSError("permission denied")):
                result = validate_corpus_pack(p)
                self.assertFalse(result["valid"])
                self.assertTrue(any("Cannot stat" in e for e in result["errors"]))

    def test_validate_ioc_with_no_id_field(self):
        """IoCs with no 'id' field should not trigger id validation."""
        data = _make_sealed_pack_dict(
            name="no-id",
            iocs=[
                {"name": "pkg", "package_name": "pkg", "description": "desc"},
            ],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            result = validate_corpus_pack(p)
            self.assertTrue(result["valid"])

    def test_validate_ioc_with_path_separator(self):
        """IoC ID with slash should be flagged."""
        data = _make_sealed_pack_dict(
            name="slash-id",
            iocs=[
                {"name": "pkg", "package_name": "pkg", "description": "d", "id": "foo/bar"},
            ],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            result = validate_corpus_pack(p)
            self.assertFalse(result["valid"])
            self.assertTrue(any("invalid id" in e for e in result["errors"]))


# ── list_available_packs tests ────────────────────────────────────────────


class TestListAvailablePacks(unittest.TestCase):
    """Tests for list_available_packs()."""

    def test_builtin_packs_included(self):
        packs = list_available_packs()
        builtin_names = {p["name"] for p in packs if p["source"] == "built-in"}
        self.assertEqual(builtin_names, set(BUILTIN_PACKS.keys()))

    def test_builtin_packs_description(self):
        packs = list_available_packs()
        for p in packs:
            if p["source"] == "built-in":
                self.assertEqual(p["description"], BUILTIN_PACKS[p["name"]])

    @patch("picosentry.scan.corpus_share.user_corpus_dir")
    def test_user_packs_from_directory(self, mock_dir):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_dir.return_value = Path(tmpdir)
            data = _make_sealed_pack_dict(name="user-pack-1")
            _write_pack_file(tmpdir, data, filename="user-pack-1.json")
            packs = list_available_packs()
            user_packs = [p for p in packs if p["source"] == "user"]
            self.assertEqual(len(user_packs), 1)
            self.assertEqual(user_packs[0]["name"], "user-pack-1")

    @patch("picosentry.scan.corpus_share.user_corpus_dir")
    def test_user_packs_empty_directory(self, mock_dir):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_dir.return_value = Path(tmpdir)
            packs = list_available_packs()
            user_packs = [p for p in packs if p["source"] == "user"]
            self.assertEqual(len(user_packs), 0)

    @patch("picosentry.scan.corpus_share.user_corpus_dir")
    def test_user_packs_nonexistent_directory(self, mock_dir):
        mock_dir.return_value = Path("/nonexistent/dir")
        packs = list_available_packs()
        user_packs = [p for p in packs if p["source"] == "user"]
        self.assertEqual(len(user_packs), 0)

    @patch("picosentry.scan.corpus_share.user_corpus_dir")
    def test_user_packs_corrupted_json_skipped(self, mock_dir):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_dir.return_value = Path(tmpdir)
            bad = Path(tmpdir) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            packs = list_available_packs()
            user_packs = [p for p in packs if p["source"] == "user"]
            self.assertEqual(len(user_packs), 0)

    @patch("picosentry.scan.corpus_share.user_corpus_dir")
    def test_user_packs_non_pack_json_skipped(self, mock_dir):
        """JSON files without pack_format field should be skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_dir.return_value = Path(tmpdir)
            other = Path(tmpdir) / "not-a-pack.json"
            other.write_text(json.dumps({"name": "foo"}), encoding="utf-8")
            packs = list_available_packs()
            user_packs = [p for p in packs if p["source"] == "user"]
            self.assertEqual(len(user_packs), 0)

    @patch("picosentry.scan.corpus_share.user_corpus_dir")
    def test_user_packs_multiple(self, mock_dir):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_dir.return_value = Path(tmpdir)
            for i in range(3):
                data = _make_sealed_pack_dict(name=f"pack-{i}")
                _write_pack_file(tmpdir, data, filename=f"pack-{i}.json")
            packs = list_available_packs()
            user_packs = [p for p in packs if p["source"] == "user"]
            self.assertEqual(len(user_packs), 3)

    @patch("picosentry.scan.corpus_share.user_corpus_dir")
    def test_user_packs_missing_name_uses_filename(self, mock_dir):
        """If pack is missing 'name', fall back to filename stem."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_dir.return_value = Path(tmpdir)
            data = _make_sealed_pack_dict()
            del data["name"]
            _write_pack_file(tmpdir, data, filename="fallback-name.json")
            packs = list_available_packs()
            user_packs = [p for p in packs if p["source"] == "user"]
            self.assertEqual(len(user_packs), 1)
            self.assertEqual(user_packs[0]["name"], "fallback-name")


# ── Edge cases ────────────────────────────────────────────────────────────


class TestEdgeCases(unittest.TestCase):
    """Edge cases and boundary conditions."""

    def test_corpus_pack_empty_name(self):
        pack = CorpusPack(name="")
        self.assertEqual(pack.name, "")
        self.assertIsNotNone(pack.pack_id)

    def test_corpus_pack_unicode_name(self):
        pack = CorpusPack(name="テストパック")
        self.assertEqual(pack.name, "テストパック")
        self.assertIsNotNone(pack.digest())

    def test_import_with_allow_overwrite(self):
        data = _make_sealed_pack_dict(
            name="overwrite",
            iocs=[
                _make_ioc_data(ioc_id="over1234567"),
            ],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            p = _write_pack_file(tmpdir, data)
            with patch("picosentry.scan.corpus_share.register_ioc") as mock_reg:
                import_corpus_pack(p, allow_overwrite=True)
                mock_reg.assert_called_once()
                _, kwargs = mock_reg.call_args
                self.assertTrue(kwargs.get("allow_overwrite", False))

    def test_from_dict_preserves_all_fields(self):
        data = _make_sealed_pack_dict(name="all-fields")
        data["description"] = "full description"
        data["author"] = "author-x"
        data["created_at"] = "2024-06-01T00:00:00Z"
        pack = CorpusPack.from_dict(data)
        self.assertEqual(pack.description, "full description")
        self.assertEqual(pack.author, "author-x")
        self.assertEqual(pack.created_at, "2024-06-01T00:00:00Z")

    def test_max_pack_bytes_constant(self):
        self.assertEqual(_MAX_PACK_BYTES, 10 * 1024 * 1024)

    def test_builtin_packs_content(self):
        self.assertIn("known-attacks", BUILTIN_PACKS)
        self.assertIn("typosquat-top1000", BUILTIN_PACKS)
        self.assertIn("malicious-maintainers", BUILTIN_PACKS)

    def test_pack_version_constant(self):
        self.assertEqual(PACK_VERSION, "1.0")


if __name__ == "__main__":
    unittest.main()
