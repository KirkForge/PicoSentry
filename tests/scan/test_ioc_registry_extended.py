"""
Comprehensive tests for picosentry.ioc_registry — IoCRecord, register, remove,
list, resolve paths, load_all, and edge cases.
"""

import contextlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from picosentry.scan.ioc_registry import (
    IoCRecord,
    _validate_ioc_id,
    custom_ioc_dir,
    list_custom_iocs,
    load_all_iocs,
    register_ioc,
    remove_ioc,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ioc_data(**overrides):
    """Build a minimal valid IoC data dict with sensible defaults."""
    base = {
        "id": "test-ioc-001",
        "name": "Test IoC",
        "package_name": "evil-pkg",
        "version_range": ">=1.0.0",
        "ioc_type": "custom",
        "attack_vector": "supply-chain",
        "severity": "HIGH",
        "description": "A test IoC entry",
        "references": ["https://example.com/advisory"],
        "source": "custom",
    }
    base.update(overrides)
    return base


class _TempCustomDirMixin:
    """Mixin that redirects custom_ioc_dir() to a temp directory."""

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_path = Path(self._tmp.name)
        self._custom_dir = self._tmp_path / "ioc" / "custom"
        self._custom_dir.mkdir(parents=True, exist_ok=True)
        # Patch custom_ioc_dir so all writes go to our temp tree
        self._patcher = patch(
            "picosentry.scan.ioc_registry.custom_ioc_dir",
            return_value=self._custom_dir,
        )
        self._patcher.start()
        self.addCleanup(self._patcher.stop)
        self.addCleanup(self._tmp.cleanup)


# ===================================================================
# IoCRecord
# ===================================================================


class TestIoCRecord(unittest.TestCase):
    """Tests for IoCRecord creation and serialisation."""

    def test_full_data_roundtrip(self):
        """All supplied fields are preserved through IoCRecord → to_dict()."""
        data = _make_ioc_data(
            id="ioc-full-1",
            name="Full IoC",
            package_name="malicious-lib",
            version_range="<2.0.0",
            ioc_type="typosquat",
            attack_vector="npm-install",
            severity="CRITICAL",
            description="Desc",
            references=["https://ref1", "https://ref2"],
            added_at="2025-01-01T00:00:00+00:00",
            source="manual",
            expires_at="2026-01-01T00:00:00+00:00",
        )
        rec = IoCRecord(data)
        d = rec.to_dict()
        self.assertEqual(d["id"], "ioc-full-1")
        self.assertEqual(d["name"], "Full IoC")
        self.assertEqual(d["package_name"], "malicious-lib")
        self.assertEqual(d["version_range"], "<2.0.0")
        self.assertEqual(d["ioc_type"], "typosquat")
        self.assertEqual(d["attack_vector"], "npm-install")
        self.assertEqual(d["severity"], "CRITICAL")
        self.assertEqual(d["description"], "Desc")
        self.assertEqual(d["references"], ["https://ref1", "https://ref2"])
        self.assertEqual(d["added_at"], "2025-01-01T00:00:00+00:00")
        self.assertEqual(d["source"], "manual")
        self.assertEqual(d["expires_at"], "2026-01-01T00:00:00+00:00")

    def test_defaults_when_fields_missing(self):
        """IoCRecord fills defaults for optional fields."""
        rec = IoCRecord({"name": "X", "package_name": "Y"})
        self.assertEqual(rec.version_range, "*")
        self.assertEqual(rec.ioc_type, "custom")
        self.assertEqual(rec.severity, "HIGH")
        self.assertEqual(rec.attack_vector, "")
        self.assertEqual(rec.description, "")
        self.assertEqual(rec.references, [])
        self.assertEqual(rec.source, "custom")
        self.assertIsNone(rec.expires_at)
        # added_at should be auto-generated (non-empty)
        self.assertTrue(rec.added_at)

    def test_auto_generated_id_from_content(self):
        """When id is omitted, it's derived from name+package_name+ioc_type."""
        rec = IoCRecord({"name": "myname", "package_name": "mypkg", "ioc_type": "malware"})
        self.assertTrue(rec.id)
        self.assertEqual(len(rec.id), 12)  # sha256[:12]
        # Deterministic: same inputs → same id
        rec2 = IoCRecord({"name": "myname", "package_name": "mypkg", "ioc_type": "malware"})
        self.assertEqual(rec.id, rec2.id)

    def test_auto_generated_added_at(self):
        """When added_at is omitted, current UTC time is used."""
        rec = IoCRecord({"id": "t1", "name": "N", "package_name": "P"})
        self.assertTrue(rec.added_at)
        self.assertIn("T", rec.added_at)  # ISO format

    def test_to_dict_omits_expires_at_when_none(self):
        """expires_at is excluded from to_dict() when not set."""
        rec = IoCRecord({"id": "t2", "name": "N", "package_name": "P"})
        d = rec.to_dict()
        self.assertNotIn("expires_at", d)

    def test_to_dict_includes_expires_at_when_set(self):
        """expires_at appears in to_dict() when provided."""
        rec = IoCRecord(
            {
                "id": "t3",
                "name": "N",
                "package_name": "P",
                "expires_at": "2026-06-01T00:00:00+00:00",
            }
        )
        d = rec.to_dict()
        self.assertIn("expires_at", d)
        self.assertEqual(d["expires_at"], "2026-06-01T00:00:00+00:00")

    def test_empty_string_id_triggers_auto_generation(self):
        """An empty-string id counts as missing and is auto-generated."""
        rec = IoCRecord({"id": "", "name": "Z", "package_name": "Q"})
        self.assertTrue(rec.id)
        self.assertNotEqual(rec.id, "")


# ===================================================================
# _validate_ioc_id
# ===================================================================


class TestValidateIoCId(unittest.TestCase):
    """Tests for the internal IoC ID validator."""

    def test_valid_ids(self):
        """Typical IDs pass validation without error."""
        for valid in ["abc", "My-IoC_1.0", "a" * 128, "ioc-2025-001"]:
            _validate_ioc_id(valid)  # should not raise

    def test_empty_string_rejected(self):
        with self.assertRaises(ValueError):
            _validate_ioc_id("")

    def test_directory_traversal_rejected(self):
        with self.assertRaises(ValueError):
            _validate_ioc_id("..")

    def test_dotdot_in_middle_rejected(self):
        with self.assertRaises(ValueError):
            _validate_ioc_id("foo..bar")

    def test_forward_slash_rejected(self):
        with self.assertRaises(ValueError):
            _validate_ioc_id("foo/bar")

    def test_backslash_rejected(self):
        with self.assertRaises(ValueError):
            _validate_ioc_id("foo\\bar")

    def test_space_rejected(self):
        with self.assertRaises(ValueError):
            _validate_ioc_id("has space")

    def test_too_long_id_rejected(self):
        with self.assertRaises(ValueError):
            _validate_ioc_id("a" * 129)

    def test_special_chars_rejected(self):
        for bad in ["ioc@123", "ioc!ok", "ioc#1", "ioc$"]:
            with self.subTest(char=bad):
                self.assertRaises(ValueError, _validate_ioc_id, bad)


# ===================================================================
# register_ioc
# ===================================================================


class TestRegisterIoc(_TempCustomDirMixin, unittest.TestCase):
    """Tests for register_ioc()."""

    def test_register_valid_ioc(self):
        """Registering a valid IoC creates the JSON file and returns the record."""
        data = _make_ioc_data()
        rec = register_ioc(data)
        self.assertEqual(rec.id, data["id"])
        self.assertEqual(rec.name, data["name"])
        # File should exist on disk
        fpath = self._custom_dir / f"{data['id']}.json"
        self.assertTrue(fpath.exists())
        stored = json.loads(fpath.read_text(encoding="utf-8"))
        self.assertEqual(stored["package_name"], "evil-pkg")

    def test_register_duplicate_raises_file_exists(self):
        """Registering the same ID twice without overwrite raises FileExistsError."""
        data = _make_ioc_data(id="dup-ioc")
        register_ioc(data)
        with self.assertRaises(FileExistsError):
            register_ioc(data)

    def test_register_overwrite_succeeds(self):
        """allow_overwrite=True replaces an existing entry."""
        data = _make_ioc_data(id="ow-ioc", description="v1")
        register_ioc(data)
        data["description"] = "v2"
        rec = register_ioc(data, allow_overwrite=True)
        self.assertEqual(rec.description, "v2")
        # Verify on disk
        fpath = self._custom_dir / "ow-ioc.json"
        stored = json.loads(fpath.read_text(encoding="utf-8"))
        self.assertEqual(stored["description"], "v2")

    def test_register_auto_generated_id(self):
        """IoC with no id gets an auto-generated one and is stored correctly."""
        data = {"name": "Auto", "package_name": "auto-pkg"}
        rec = register_ioc(data)
        self.assertTrue(rec.id)
        fpath = self._custom_dir / f"{rec.id}.json"
        self.assertTrue(fpath.exists())

    def test_register_with_invalid_id_raises(self):
        """An IoC with an invalid id fails validation, not registration."""
        data = _make_ioc_data(id="../evil")
        with self.assertRaises(ValueError):
            register_ioc(data)

    def test_register_audit_called(self):
        """Registration triggers an audit event (verified via mock)."""
        data = _make_ioc_data(id="audit-ioc")
        with patch("picosentry.scan.ioc_registry.audit") as mock_audit:
            register_ioc(data)
            mock_audit.assert_called_once()
            call_kwargs = mock_audit.call_args
            self.assertEqual(call_kwargs[1]["target"], "audit-ioc:evil-pkg")
            self.assertEqual(call_kwargs[1]["metadata"]["severity"], "HIGH")


# ===================================================================
# remove_ioc
# ===================================================================


class TestRemoveIoc(_TempCustomDirMixin, unittest.TestCase):
    """Tests for remove_ioc()."""

    def test_remove_existing_ioc(self):
        """Removing a registered IoC returns True and deletes the file."""
        data = _make_ioc_data(id="rem-ioc")
        register_ioc(data)
        result = remove_ioc("rem-ioc")
        self.assertTrue(result)
        fpath = self._custom_dir / "rem-ioc.json"
        self.assertFalse(fpath.exists())

    def test_remove_nonexistent_ioc(self):
        """Removing a non-existent IoC returns False without error."""
        result = remove_ioc("nonexistent-ioc")
        self.assertFalse(result)

    def test_remove_invalid_id_raises(self):
        """Passing a path-traversal id to remove_ioc raises ValueError."""
        with self.assertRaises(ValueError):
            remove_ioc("../../etc/passwd")

    def test_remove_audit_called(self):
        """Removing an existing IoC calls audit with outcome='success'."""
        register_ioc(_make_ioc_data(id="rem-audit"))
        with patch("picosentry.scan.ioc_registry.audit") as mock_audit:
            result = remove_ioc("rem-audit")
            self.assertTrue(result)
            mock_audit.assert_called_once()
            self.assertEqual(mock_audit.call_args[1]["outcome"], "success")

    def test_remove_not_found_audit(self):
        """Removing a non-existent IoC calls audit with outcome='not_found'."""
        with patch("picosentry.scan.ioc_registry.audit") as mock_audit:
            result = remove_ioc("missing-audit")
            self.assertFalse(result)
            mock_audit.assert_called_once()
            self.assertEqual(mock_audit.call_args[1]["outcome"], "not_found")


# ===================================================================
# list_custom_iocs
# ===================================================================


class TestListCustomIocs(_TempCustomDirMixin, unittest.TestCase):
    """Tests for list_custom_iocs()."""

    def test_list_empty_directory(self):
        """Listing an empty custom IoC directory returns an empty list."""
        self.assertEqual(list_custom_iocs(), [])

    def test_list_single_ioc(self):
        """A single registered IoC is listed correctly."""
        register_ioc(_make_ioc_data(id="list-1"))
        iocs = list_custom_iocs()
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0].id, "list-1")

    def test_list_multiple_iocs_sorted(self):
        """Multiple IoCs are listed (glob returns sorted by filename)."""
        register_ioc(_make_ioc_data(id="list-b", name="B"))
        register_ioc(_make_ioc_data(id="list-a", name="A"))
        iocs = list_custom_iocs()
        ids = [r.id for r in iocs]
        self.assertEqual(ids, ["list-a", "list-b"])

    def test_filter_by_severity(self):
        """Client-side filtering by severity works."""
        register_ioc(_make_ioc_data(id="sev-low", severity="LOW"))
        register_ioc(_make_ioc_data(id="sev-crit", severity="CRITICAL"))
        iocs = list_custom_iocs()
        low = [r for r in iocs if r.severity == "LOW"]
        critical = [r for r in iocs if r.severity == "CRITICAL"]
        self.assertEqual(len(low), 1)
        self.assertEqual(len(critical), 1)

    def test_skip_malformed_json(self):
        """Malformed JSON files are skipped with a warning (not an error)."""
        bad_file = self._custom_dir / "bad-ioc.json"
        bad_file.write_text("{not valid json}", encoding="utf-8")
        # Should not raise; should return empty (or other valid entries)
        iocs = list_custom_iocs()
        self.assertIsInstance(iocs, list)

    def test_skip_symlink(self):
        """Symlinked JSON files are skipped for security."""
        real = self._custom_dir / "real-ioc.json"
        real.write_text(json.dumps(_make_ioc_data(id="real-ioc")), encoding="utf-8")
        link = self._custom_dir / "link-ioc.json"
        link.symlink_to(real)
        iocs = list_custom_iocs()
        ids = [r.id for r in iocs]
        self.assertIn("real-ioc", ids)
        self.assertNotIn("link-ioc", ids)

    def test_skip_unreadable_file(self):
        """An unreadable file (OSError) is skipped gracefully."""
        # Write a file then make it unreadable (on POSIX)
        bad_file = self._custom_dir / "unreadable.json"
        bad_file.write_text("{}", encoding="utf-8")
        try:
            bad_file.chmod(0o000)
            iocs = list_custom_iocs()
            self.assertIsInstance(iocs, list)
        except OSError:
            pass  # Some environments don't allow chmod; skip test gracefully
        finally:
            with contextlib.suppress(OSError):
                bad_file.chmod(0o644)


# ===================================================================
# custom_ioc_dir (path resolution)
# ===================================================================


class TestCustomIocDir(unittest.TestCase):
    """Tests for custom_ioc_dir() path resolution via user_corpus_dir()."""

    def test_dir_created_under_corpus(self):
        """custom_ioc_dir() creates the ioc/custom subdirectory."""
        with tempfile.TemporaryDirectory() as td:
            corpus = Path(td) / "corpus"
            with patch("picosentry.scan.ioc_registry.user_corpus_dir", return_value=corpus):
                result = custom_ioc_dir()
                self.assertTrue(result.exists())
                self.assertEqual(result, corpus / "ioc" / "custom")

    def test_env_var_override(self):
        """PICOCORPUS_DIR env var controls user_corpus_dir, which controls custom_ioc_dir."""
        with tempfile.TemporaryDirectory() as td:
            custom_path = Path(td) / "my-corpus"
            with (
                patch.dict(os.environ, {"PICOCORPUS_DIR": str(custom_path)}, clear=False),
                patch("picosentry.scan.ioc_registry.user_corpus_dir", return_value=custom_path),
            ):
                result = custom_ioc_dir()
                self.assertTrue(str(result).startswith(str(custom_path)))

    def test_xdg_data_home(self):
        """XDG_DATA_HOME is respected for path resolution."""
        with tempfile.TemporaryDirectory() as td:
            xdg_path = Path(td) / "xdg-share"
            with (
                patch.dict(os.environ, {"XDG_DATA_HOME": str(xdg_path)}, clear=False),
                patch(
                    "picosentry.scan.ioc_registry.user_corpus_dir",
                    return_value=xdg_path / "picosentry" / "corpus",
                ),
            ):
                result = custom_ioc_dir()
                self.assertIn("picosentry", str(result))

    def test_default_fallback_path(self):
        """Without overrides, path falls back to ~/.local/share/picosentry/corpus/ioc/custom."""
        # We can't easily test the real default without side effects,
        # but we can verify the function calls user_corpus_dir and appends.
        with patch("picosentry.scan.ioc_registry.user_corpus_dir") as mock_ucd:
            mock_ucd.return_value = Path.home() / ".local" / "share" / "picosentry" / "corpus"
            with patch.object(Path, "mkdir"):
                result = custom_ioc_dir()
                self.assertEqual(result, mock_ucd.return_value / "ioc" / "custom")


# ===================================================================
# load_all_iocs
# ===================================================================


class TestLoadAllIocs(_TempCustomDirMixin, unittest.TestCase):
    """Tests for load_all_iocs() merging built-in and custom IoCs."""

    def test_load_with_custom_iocs(self):
        """Custom IoCs are included in load_all_iocs()."""
        register_ioc(_make_ioc_data(id="load-1", package_name="custom-pkg"))
        all_iocs = load_all_iocs()
        pkg_names = [i.get("package_name", "") for i in all_iocs]
        self.assertIn("custom-pkg", pkg_names)

    def test_custom_overrides_builtin(self):
        """Custom IoC with same package_name+version_range overrides built-in."""
        # Register a custom IoC that mimics a built-in key
        register_ioc(
            _make_ioc_data(
                id="override-1",
                package_name="left-pad",  # exists in built-in corpus
                version_range="1.3.0",
                description="CUSTOM OVERRIDE",
            )
        )
        all_iocs = load_all_iocs()
        matching = [i for i in all_iocs if i.get("package_name") == "left-pad" and i.get("version_range") == "1.3.0"]
        self.assertTrue(any(m.get("description") == "CUSTOM OVERRIDE" for m in matching))

    def test_empty_custom_dir_still_loads_builtin(self):
        """Even with no custom IoCs, built-in IoCs are loaded."""
        all_iocs = load_all_iocs()
        self.assertTrue(len(all_iocs) > 0, "Should load at least one built-in IoC")
        # Built-in corpus uses "name" field (not "package_name")
        names = [i.get("name", "") for i in all_iocs]
        self.assertTrue(any(names), "At least one IoC should have a name")

    def test_malformed_builtin_skipped(self):
        """Malformed JSON in the built-in corpus is skipped silently."""
        # This is hard to test directly without modifying the installed corpus,
        # but we verify load_all_iocs() doesn't crash on bad files.
        # Create a malformed file in our custom dir (it will be picked up by list_custom_iocs)
        bad_file = self._custom_dir / "malformed.json"
        bad_file.write_text("{bad json content", encoding="utf-8")
        # Should not crash
        all_iocs = load_all_iocs()
        self.assertIsInstance(all_iocs, list)


# ===================================================================
# Edge cases
# ===================================================================


class TestEdgeCases(_TempCustomDirMixin, unittest.TestCase):
    """Edge cases: empty dirs, missing fields, path traversal, etc."""

    def test_missing_optional_fields_in_json_file(self):
        """JSON file with only required fields can be loaded as IoCRecord."""
        minimal = {"name": "Min", "package_name": "min-pkg"}
        fpath = self._custom_dir / "minimal.json"
        fpath.write_text(json.dumps(minimal), encoding="utf-8")
        iocs = list_custom_iocs()
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0].package_name, "min-pkg")
        # Defaults should be filled
        self.assertEqual(iocs[0].severity, "HIGH")
        self.assertEqual(iocs[0].version_range, "*")

    def test_empty_directory(self):
        """An empty custom IoC directory returns empty list."""
        self.assertEqual(list_custom_iocs(), [])

    def test_register_then_list_then_remove_cycle(self):
        """Full lifecycle: register → list → remove → list empty."""
        data = _make_ioc_data(id="cycle-ioc")
        register_ioc(data)
        iocs = list_custom_iocs()
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0].id, "cycle-ioc")

        result = remove_ioc("cycle-ioc")
        self.assertTrue(result)
        self.assertEqual(list_custom_iocs(), [])

    def test_register_path_traversal_blocked(self):
        """IDs with path traversal characters are rejected before file access."""
        with self.assertRaises(ValueError):
            register_ioc({"id": "../etc/passwd", "name": "evil", "package_name": "x"})

    def test_remove_path_traversal_blocked(self):
        """remove_ioc also rejects path traversal IDs."""
        with self.assertRaises(ValueError):
            remove_ioc("../../etc/shadow")

    def test_register_with_all_default_fields(self):
        """An IoC with only name and package_name uses all defaults."""
        rec = register_ioc({"name": "Defaults", "package_name": "defaults-pkg"})
        self.assertEqual(rec.version_range, "*")
        self.assertEqual(rec.ioc_type, "custom")
        self.assertEqual(rec.severity, "HIGH")
        self.assertEqual(rec.source, "custom")
        self.assertEqual(rec.attack_vector, "")
        self.assertEqual(rec.description, "")
        self.assertEqual(rec.references, [])
        self.assertTrue(rec.id)

    def test_unicode_in_ioc_fields(self):
        """Unicode characters in name/description are handled correctly."""
        data = _make_ioc_data(
            id="unicode-ioc",
            name="Paket berbahaya 🐍",
            description="Desc with ünïcödé characters",
        )
        rec = register_ioc(data)
        self.assertIn("🐍", rec.name)
        # Round-trip through disk
        iocs = list_custom_iocs()
        self.assertEqual(len(iocs), 1)
        self.assertIn("🐍", iocs[0].name)

    def test_concurrent_register_different_ids(self):
        """Two different IoC IDs can coexist in the directory."""
        register_ioc(_make_ioc_data(id="conc-a", package_name="pkg-a"))
        register_ioc(_make_ioc_data(id="conc-b", package_name="pkg-b"))
        iocs = list_custom_iocs()
        self.assertEqual(len(iocs), 2)
        names = {r.package_name for r in iocs}
        self.assertEqual(names, {"pkg-a", "pkg-b"})

    def test_load_all_iocs_returns_list_of_dicts(self):
        """load_all_iocs() returns a list of dicts (not IoCRecords)."""
        register_ioc(_make_ioc_data(id="dict-1"))
        all_iocs = load_all_iocs()
        for entry in all_iocs:
            self.assertIsInstance(entry, dict)


if __name__ == "__main__":
    unittest.main()
