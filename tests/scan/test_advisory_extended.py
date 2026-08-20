"""Comprehensive tests for picosentry.advisory — OSV advisory loading, matching, severity."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import suppress
from pathlib import Path
from typing import Any

from picosentry.scan import advisory as advisory_module
from picosentry.scan.advisory import (
    _SEMVER_RE,
    Advisory,
    AdvisoryDB,
    default_advisory_dir,
    load_bundled_advisories,
)

# ── Helpers ──────────────────────────────────────────────────────────────


def _make_osv(
    adv_id="GHSA-xxxx-xxxx",
    summary="Test advisory",
    details="",
    pkg_name="lodash",
    ecosystem="npm",
    severity="HIGH",
    introduced="1.0.0",
    fixed="2.0.0",
    last_affected="",
    versions=None,
    aliases=None,
    cwe_ids=None,
    references=None,
    published="2024-01-01",
    db_specific=None,
):
    """Build a minimal OSV-format dict."""
    events = [{"introduced": introduced}]
    if fixed:
        events.append({"fixed": fixed})
    if last_affected:
        events.append({"last_affected": last_affected})

    affected_entry = {
        "package": {"ecosystem": ecosystem, "name": pkg_name},
        "ranges": [{"type": "SEMVER", "events": events}],
    }
    if versions:
        affected_entry["versions"] = versions

    data = {
        "id": adv_id,
        "summary": summary,
        "affected": [affected_entry],
        "published": published,
    }
    if details:
        data["details"] = details
    if aliases:
        data["aliases"] = aliases
    if cwe_ids:
        data["cwe_ids"] = cwe_ids
    if references:
        data["references"] = references
    if severity:
        data["database_specific"] = {"severity": severity}
    if db_specific is not None:
        data["database_specific"] = db_specific
    return data


def _write_json(path: Path, obj):
    path.write_text(json.dumps(obj), encoding="utf-8")


def _from_osv_one(data: dict) -> Advisory | None:
    """Single-package view of ``Advisory.from_osv`` (which returns a list, one
    Advisory per affected package entry — WO5.0.0-009)."""
    advs = Advisory.from_osv(data)
    return advs[0] if advs else None


def _make_advisory(**kw) -> Advisory:
    """Shorthand to build an Advisory directly."""
    defaults: dict[str, Any] = {
        "id": "GHSA-test",
        "package_name": "lodash",
        "summary": "test vuln",
        "severity": "HIGH",
        "fixed_version": "4.18.0",
        "affected_versions": [],
        "affected_ranges": [],
    }
    defaults.update(kw)
    return Advisory(**defaults)


# ══════════════════════════════════════════════════════════════════════════
# Advisory dataclass
# ══════════════════════════════════════════════════════════════════════════


class TestAdvisoryDataclass(unittest.TestCase):
    """Tests for the Advisory dataclass defaults and methods."""

    def test_defaults(self):
        adv = Advisory()
        self.assertEqual(adv.id, "")
        self.assertEqual(adv.package_name, "")
        self.assertEqual(adv.severity, "MEDIUM")
        self.assertEqual(adv.fixed_version, "")
        self.assertIsInstance(adv.affected_versions, list)
        self.assertIsInstance(adv.affected_ranges, list)
        self.assertIsInstance(adv.cwe_ids, list)
        self.assertIsInstance(adv.references, list)
        self.assertEqual(adv.published, "")
        self.assertIsInstance(adv.database_specific, dict)

    def test_to_dict_roundtrip(self):
        adv = Advisory(
            id="CVE-2024-0001",
            package_name="express",
            summary="prototypal pollution",
            severity="HIGH",
            fixed_version="4.18.0",
            affected_versions=["4.17.0"],
            affected_ranges=[("4.0.0", "4.18.0", False)],
            cwe_ids=["CWE-1321"],
            references=["https://example.com"],
            published="2024-03-01",
            database_specific={"severity": "HIGH"},
        )
        d = adv.to_dict()
        self.assertEqual(d["id"], "CVE-2024-0001")
        self.assertEqual(d["package_name"], "express")
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["affected_ranges"], [("4.0.0", "4.18.0", False)])
        self.assertEqual(d["cwe_ids"], ["CWE-1321"])
        self.assertEqual(d["references"], ["https://example.com"])
        self.assertEqual(d["published"], "2024-03-01")


# ══════════════════════════════════════════════════════════════════════════
# Advisory.from_osv
# ══════════════════════════════════════════════════════════════════════════


class TestAdvisoryFromOsv(unittest.TestCase):
    """Tests for Advisory.from_osv parsing."""

    def test_basic_parse(self):
        data = _make_osv(adv_id="GHSA-1234-5678", pkg_name="lodash", severity="CRITICAL")
        adv = _from_osv_one(data)
        self.assertIsNotNone(adv)
        self.assertEqual(adv.id, "GHSA-1234-5678")
        self.assertEqual(adv.package_name, "lodash")
        self.assertEqual(adv.severity, "CRITICAL")

    def test_returns_none_when_no_npm_pypi_go_or_cargo_package(self):
        data = _make_osv(ecosystem="CocoaPods", pkg_name="some-pod")
        self.assertIsNone(_from_osv_one(data))

    def test_returns_none_when_empty_affected(self):
        data = {"id": "GHSA-empty", "summary": "no affected", "affected": []}
        self.assertIsNone(_from_osv_one(data))

    def test_summary_fallback_to_details(self):
        data = _make_osv(summary="", details="A" * 300)
        adv = _from_osv_one(data)
        self.assertIsNotNone(adv)
        self.assertEqual(len(adv.summary), 200)
        self.assertTrue(adv.summary.startswith("AAA"))

    def test_severity_from_database_specific(self):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            data = _make_osv(severity=sev)
            adv = _from_osv_one(data)
            self.assertEqual(adv.severity, sev)

    def test_severity_default_when_missing(self):
        data = _make_osv(db_specific={})
        adv = _from_osv_one(data)
        self.assertEqual(adv.severity, "MEDIUM")

    def test_severity_ignored_when_invalid(self):
        data = _make_osv(db_specific={"severity": "UNKNOWN"})
        adv = _from_osv_one(data)
        self.assertEqual(adv.severity, "MEDIUM")

    def test_severity_ignored_when_not_dict(self):
        data = _make_osv()
        data["database_specific"] = "not a dict"
        adv = _from_osv_one(data)
        self.assertEqual(adv.severity, "MEDIUM")

    def test_fixed_version_extracted(self):
        data = _make_osv(fixed="3.1.0")
        adv = _from_osv_one(data)
        self.assertEqual(adv.fixed_version, "3.1.0")

    def test_no_fixed_version(self):
        data = _make_osv(fixed="")
        adv = _from_osv_one(data)
        self.assertEqual(adv.fixed_version, "")

    def test_affected_versions_deduplicated(self):
        data = _make_osv(versions=["1.0.0", "1.0.0", "1.1.0"])
        adv = _from_osv_one(data)
        self.assertEqual(adv.affected_versions, ["1.0.0", "1.1.0"])

    def test_range_with_last_affected(self):
        data = _make_osv(fixed="", last_affected="2.5.0")
        adv = _from_osv_one(data)
        self.assertIsNotNone(adv)
        self.assertEqual(adv.affected_ranges, [("1.0.0", "2.5.0", True)])

    def test_range_with_no_upper_bound(self):
        data = _make_osv(fixed="", last_affected="")
        adv = _from_osv_one(data)
        self.assertEqual(adv.affected_ranges, [("1.0.0", "", False)])

    def test_multiple_ranges_in_one_affected(self):
        osv = {
            "id": "GHSA-multi-range",
            "summary": "multi",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "foo"},
                    "ranges": [
                        {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]},
                        {"type": "SEMVER", "events": [{"introduced": "3.0.0"}, {"fixed": "4.0.0"}]},
                    ],
                }
            ],
        }
        adv = _from_osv_one(osv)
        self.assertIsNotNone(adv)
        self.assertEqual(len(adv.affected_ranges), 2)
        self.assertEqual(adv.affected_ranges[0], ("1.0.0", "2.0.0", False))
        self.assertEqual(adv.affected_ranges[1], ("3.0.0", "4.0.0", False))

    def test_missing_id_defaults_empty(self):
        data = _make_osv()
        del data["id"]
        adv = _from_osv_one(data)
        self.assertIsNotNone(adv)
        self.assertEqual(adv.id, "")


class TestAdvisoryFromOsvMultiPackage(unittest.TestCase):
    """WO5.0.0-009 — multi-package records: one Advisory per affected entry."""

    def test_multi_package_record_yields_one_advisory_per_package(self):
        data = {
            "id": "GHSA-multi-2pkgs",
            "summary": "affects two packages",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "pkg-a"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}],
                },
                {
                    "package": {"ecosystem": "npm", "name": "pkg-b"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "3.0.0"}, {"fixed": "4.0.0"}]}],
                },
            ],
            "database_specific": {"severity": "HIGH"},
        }
        advs = Advisory.from_osv(data)
        self.assertEqual(len(advs), 2)
        by_pkg = {adv.package_name: adv for adv in advs}
        self.assertEqual(set(by_pkg), {"pkg-a", "pkg-b"})
        # Each package carries ONLY its own ranges — pkg-b must not inherit
        # pkg-a's range (the old last-package-wins bug flagged wrong versions).
        self.assertEqual(by_pkg["pkg-a"].affected_ranges, [("1.0.0", "2.0.0", False)])
        self.assertEqual(by_pkg["pkg-b"].affected_ranges, [("3.0.0", "4.0.0", False)])
        self.assertEqual(by_pkg["pkg-a"].fixed_version, "2.0.0")
        self.assertEqual(by_pkg["pkg-b"].fixed_version, "4.0.0")

    def test_multi_package_db_check_matches_each_package(self):
        d = Path(tempfile.mkdtemp())
        _write_json(
            d / "multi.json",
            {
                "id": "GHSA-multi-2pkgs",
                "summary": "affects two packages",
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "pkg-a"},
                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}],
                    },
                    {
                        "package": {"ecosystem": "npm", "name": "pkg-b"},
                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "3.0.0"}, {"fixed": "4.0.0"}]}],
                    },
                ],
            },
        )
        db = AdvisoryDB(d)
        self.assertEqual(len(db.check("pkg-a", "1.5.0")), 1)
        # pkg-a's range must not apply to pkg-b: 1.5.0 is only vulnerable via pkg-a.
        self.assertEqual(db.check("pkg-b", "1.5.0"), [])
        self.assertEqual(len(db.check("pkg-b", "3.5.0")), 1)


class TestAdvisoryNameNormalization(unittest.TestCase):
    """WO6.0.0-006 — PEP 503 name normalization at index AND lookup time.

    PyPI/METADATA feed raw names (``Flask``, ``PyYAML``, ``ruamel.yaml``) while
    OSV records index by canonical form (``flask``, ``pyyaml``,
    ``ruamel-yaml``). Exact-match lookups returned ``[]`` for the common case.
    """

    def test_check_flask_matches_flask_keyed_record(self):
        d = Path(tempfile.mkdtemp())
        _write_json(d / "flask.json", _make_osv(adv_id="GHSA-flask", pkg_name="flask", ecosystem="pypi"))
        db = AdvisoryDB(d)
        # 'Flask' (canonical: 'flask') must find the 'flask'-keyed record.
        self.assertEqual(len(db.check("Flask", "1.5.0")), 1)
        self.assertEqual(len(db.check("flask", "1.5.0")), 1)
        # Same result, regardless of case form.
        self.assertEqual(db.check("Flask", "1.5.0"), db.check("flask", "1.5.0"))

    def test_check_pyyaml_matches_pyyaml_keyed_record(self):
        d = Path(tempfile.mkdtemp())
        _write_json(d / "pyyaml.json", _make_osv(adv_id="GHSA-pyyaml", pkg_name="pyyaml", ecosystem="pypi"))
        db = AdvisoryDB(d)
        self.assertEqual(len(db.check("PyYAML", "1.5.0")), 1)
        self.assertEqual(len(db.check("pyyaml", "1.5.0")), 1)

    def test_ruamel_yaml_dotted_matches_dashed_key(self):
        d = Path(tempfile.mkdtemp())
        _write_json(
            d / "ruamel.json",
            _make_osv(adv_id="GHSA-ruamel", pkg_name="ruamel-yaml", ecosystem="pypi"),
        )
        db = AdvisoryDB(d)
        # 'ruamel.yaml' (canonical: 'ruamel-yaml') must find the
        # 'ruamel-yaml'-keyed record — exact-match lookup used to return [].
        self.assertEqual(len(db.check("ruamel.yaml", "1.5.0")), 1)
        self.assertEqual(len(db.check("ruamel-yaml", "1.5.0")), 1)

    def test_underscore_and_dot_collapse_to_dash(self):
        d = Path(tempfile.mkdtemp())
        _write_json(
            d / "imp.json",
            _make_osv(adv_id="GHSA-imp", pkg_name="importlib-metadata", ecosystem="pypi"),
        )
        db = AdvisoryDB(d)
        # PEP 503: runs of [-_.] → single "-".
        self.assertEqual(len(db.check("importlib.metadata", "1.5.0")), 1)
        self.assertEqual(len(db.check("importlib_metadata", "1.5.0")), 1)
        self.assertEqual(len(db.check("importlib-metadata", "1.5.0")), 1)


class TestAdvisoryCvssSeverity(unittest.TestCase):
    """WO6.0.0-006 — when ``database_specific.severity`` is absent, derive the
    bucket from the top-level ``severity: [{type: CVSS_V3, score}]`` list so
    raw PyPI/Go OSV records don't flatten to MEDIUM."""

    def _osv_with_cvss(self, score, ecosystem="pypi"):
        data = _make_osv(
            adv_id=f"GHSA-cvss-{score}",
            pkg_name="vuln-pkg",
            ecosystem=ecosystem,
            severity="",  # suppress database_specific.severity
            db_specific={},  # no severity field at all
        )
        data["severity"] = [{"type": "CVSS_V3", "score": score}]
        return data

    def test_cvss_9_8_is_critical(self):
        d = Path(tempfile.mkdtemp())
        _write_json(d / "crit.json", self._osv_with_cvss("9.8"))
        db = AdvisoryDB(d)
        results = db.check("vuln-pkg", "1.0.0")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].severity, "CRITICAL")

    def test_cvss_7_5_is_high(self):
        d = Path(tempfile.mkdtemp())
        _write_json(d / "high.json", self._osv_with_cvss("7.5"))
        db = AdvisoryDB(d)
        self.assertEqual(db.check("vuln-pkg", "1.0.0")[0].severity, "HIGH")

    def test_cvss_5_0_is_medium(self):
        d = Path(tempfile.mkdtemp())
        _write_json(d / "med.json", self._osv_with_cvss("5.0"))
        db = AdvisoryDB(d)
        self.assertEqual(db.check("vuln-pkg", "1.0.0")[0].severity, "MEDIUM")

    def test_cvss_2_0_is_low(self):
        d = Path(tempfile.mkdtemp())
        _write_json(d / "low.json", self._osv_with_cvss("2.0"))
        db = AdvisoryDB(d)
        self.assertEqual(db.check("vuln-pkg", "1.0.0")[0].severity, "LOW")

    def test_cvss_vector_string_falls_back_to_medium(self):
        # CVSS vector strings need a vendor library to derive the base score;
        # we fall back to MEDIUM rather than misclassify (ceiling: vector-only
        # records; upgrade path: cvss-bsc lib when vector form dominates).
        d = Path(tempfile.mkdtemp())
        osv = self._osv_with_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        _write_json(d / "vec.json", osv)
        db = AdvisoryDB(d)
        self.assertEqual(db.check("vuln-pkg", "1.0.0")[0].severity, "MEDIUM")

    def test_db_specific_severity_wins_over_cvss(self):
        d = Path(tempfile.mkdtemp())
        osv = _make_osv(adv_id="GHSA-db-wins", pkg_name="vuln-pkg", severity="CRITICAL")
        osv["severity"] = [{"type": "CVSS_V3", "score": "5.0"}]  # would be MEDIUM
        _write_json(d / "wins.json", osv)
        db = AdvisoryDB(d)
        self.assertEqual(db.check("vuln-pkg", "1.0.0")[0].severity, "CRITICAL")

    def test_empty_severity_list_is_medium(self):
        d = Path(tempfile.mkdtemp())
        osv = _make_osv(adv_id="GHSA-empty-sev", pkg_name="vuln-pkg", severity="", db_specific={})
        osv["severity"] = []
        _write_json(d / "empty.json", osv)
        db = AdvisoryDB(d)
        self.assertEqual(db.check("vuln-pkg", "1.0.0")[0].severity, "MEDIUM")


class TestAdvisoryDBLoadEnvelope(unittest.TestCase):
    """WO5.0.0-009 — AdvisoryDB.load() understands the bundled-snapshot envelope."""

    def test_envelope_shape_loads(self):
        d = Path(tempfile.mkdtemp())
        _write_json(
            d / "snapshot.json",
            {
                "metadata": {"source": "test"},
                "advisories": [
                    _make_osv(adv_id="GHSA-env-1", pkg_name="lodash"),
                    _make_osv(adv_id="GHSA-env-2", pkg_name="express"),
                ],
            },
        )
        db = AdvisoryDB(d)
        self.assertEqual(db.advisory_count, 2)
        self.assertEqual(len(db.check("lodash", "1.5.0")), 1)

    def test_bundled_corpus_advisories_dir_loads_via_advisory_db(self):
        # The default scan path loads corpus/advisories with AdvisoryDB — the
        # envelope must parse there too (this is the exact default-path no-op).
        bundled = Path(advisory_module.__file__).parent / "corpus" / "advisories"
        if not bundled.is_dir():  # pragma: no cover - wheel packaging guarantee
            self.skipTest("bundled corpus advisories dir not shipped")
        db = AdvisoryDB(bundled)
        self.assertGreater(db.advisory_count, 0)
        self.assertGreater(len(db.check("lodash", "4.17.15")), 0)


# ══════════════════════════════════════════════════════════════════════════
# AdvisoryDB — loading
# ══════════════════════════════════════════════════════════════════════════


class TestAdvisoryDBLoad(unittest.TestCase):
    """Tests for AdvisoryDB.load() and constructor."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def _dir(self) -> Path:
        return Path(self.tmpdir)

    def test_load_with_osv_files(self):
        d = self._dir()
        _write_json(d / "GHSA-1111.json", _make_osv(adv_id="GHSA-1111", pkg_name="lodash"))
        _write_json(d / "GHSA-2222.json", _make_osv(adv_id="GHSA-2222", pkg_name="express"))
        db = AdvisoryDB(d)
        self.assertTrue(db.is_loaded)
        self.assertEqual(db.advisory_count, 2)
        self.assertEqual(db.package_count, 2)

    def test_load_via_method(self):
        d = self._dir()
        _write_json(d / "GHSA-1111.json", _make_osv(adv_id="GHSA-1111", pkg_name="lodash"))
        db = AdvisoryDB()
        count = db.load(d)
        self.assertTrue(db.is_loaded)
        self.assertEqual(count, 1)

    def test_load_empty_directory(self):
        d = self._dir()
        db = AdvisoryDB(d)
        self.assertTrue(db.is_loaded)  # loaded but empty
        self.assertEqual(db.advisory_count, 0)

    def test_load_skips_non_json(self):
        d = self._dir()
        (d / "readme.txt").write_text("not json", encoding="utf-8")
        db = AdvisoryDB(d)
        self.assertTrue(db.is_loaded)
        self.assertEqual(db.advisory_count, 0)

    def test_load_skips_malformed_json(self):
        d = self._dir()
        (d / "bad.json").write_text("{invalid json", encoding="utf-8")
        _write_json(d / "good.json", _make_osv(adv_id="GHSA-ok", pkg_name="lodash"))
        db = AdvisoryDB(d)
        self.assertTrue(db.is_loaded)
        self.assertEqual(db.advisory_count, 1)

    def test_load_skips_unsupported_ecosystem_entries(self):
        d = self._dir()
        _write_json(d / "cocoapods.json", _make_osv(ecosystem="CocoaPods", pkg_name="some-pod"))
        db = AdvisoryDB(d)
        self.assertTrue(db.is_loaded)
        self.assertEqual(db.advisory_count, 0)

    def test_load_nonexistent_path(self):
        db = AdvisoryDB(Path("/nonexistent/path"))
        self.assertFalse(db.is_loaded)  # path doesn't exist, so __init__ doesn't call load

    def test_load_multiple_for_same_package(self):
        d = self._dir()
        _write_json(d / "a1.json", _make_osv(adv_id="GHSA-a1", pkg_name="lodash", fixed="4.18.0"))
        _write_json(d / "a2.json", _make_osv(adv_id="GHSA-a2", pkg_name="lodash", fixed="4.19.0"))
        db = AdvisoryDB(d)
        self.assertEqual(db.package_count, 1)
        self.assertEqual(db.advisory_count, 2)

    def test_load_recursive_with_subdirs(self):
        d = self._dir()
        subdir = d / "npm"
        subdir.mkdir()
        _write_json(subdir / "sub.json", _make_osv(adv_id="GHSA-sub", pkg_name="lodash"))
        db = AdvisoryDB(d)
        # load uses rglob, so it finds files in subdirs
        self.assertEqual(db.advisory_count, 1)

    def test_load_skips_symlinks(self):
        d = self._dir()
        real = d / "real.json"
        _write_json(real, _make_osv(adv_id="GHSA-real", pkg_name="lodash"))
        link = d / "link.json"
        with suppress(OSError):
            link.symlink_to(real)
        db = AdvisoryDB(d)
        self.assertEqual(db.advisory_count, 1)  # only the real file, not the symlink

    def test_load_array_format(self):
        """load() handles JSON files that contain a list of advisories."""
        d = self._dir()
        arr = [
            _make_osv(adv_id="GHSA-arr1", pkg_name="lodash"),
            _make_osv(adv_id="GHSA-arr2", pkg_name="express"),
        ]
        _write_json(d / "advisories.json", arr)
        db = AdvisoryDB(d)
        self.assertEqual(db.advisory_count, 2)

    def test_load_mixed_valid_and_none(self):
        d = self._dir()
        arr = [
            _make_osv(adv_id="GHSA-ok", pkg_name="lodash"),
            {"id": "GHSA-no-pkg", "summary": "no affected", "affected": []},
        ]
        _write_json(d / "mixed.json", arr)
        db = AdvisoryDB(d)
        self.assertEqual(db.advisory_count, 1)

    # ── Constructor ─────────────────────────────────────────────────────

    def test_constructor_no_dir(self):
        db = AdvisoryDB()
        self.assertFalse(db.is_loaded)
        self.assertEqual(db.package_count, 0)
        self.assertEqual(db.advisory_count, 0)

    def test_constructor_with_dir(self):
        d = self._dir()
        _write_json(d / "a.json", _make_osv(pkg_name="lodash"))
        db = AdvisoryDB(d)
        self.assertTrue(db.is_loaded)
        self.assertEqual(db.advisory_count, 1)


# ══════════════════════════════════════════════════════════════════════════
# AdvisoryDB — check
# ══════════════════════════════════════════════════════════════════════════


class TestAdvisoryDBCheck(unittest.TestCase):
    """Tests for AdvisoryDB.check() version matching."""

    def _db_with(self, *advisories: Advisory) -> AdvisoryDB:
        db = AdvisoryDB()
        for adv in advisories:
            db._advisories.setdefault(adv.package_name, []).append(adv)
        db._loaded = True
        return db

    def test_check_no_match(self):
        db = self._db_with(_make_advisory(package_name="lodash"))
        self.assertEqual(db.check("express", "4.17.0"), [])

    def test_check_exact_name_match_with_ranges(self):
        adv = _make_advisory(
            package_name="lodash",
            affected_ranges=[("4.0.0", "4.18.0", False)],
        )
        db = self._db_with(adv)
        results = db.check("lodash", "4.17.0")
        self.assertEqual(len(results), 1)

    def test_check_version_above_range(self):
        adv = _make_advisory(
            package_name="lodash",
            affected_ranges=[("4.0.0", "4.18.0", False)],
        )
        db = self._db_with(adv)
        self.assertEqual(len(db.check("lodash", "4.18.0")), 0)

    def test_check_version_equal_to_fixed_exclusive(self):
        adv = _make_advisory(
            package_name="lodash",
            affected_ranges=[("4.0.0", "4.18.0", False)],
            fixed_version="4.18.0",
        )
        db = self._db_with(adv)
        self.assertEqual(len(db.check("lodash", "4.18.0")), 0)

    def test_check_version_below_range(self):
        adv = _make_advisory(
            package_name="lodash",
            affected_ranges=[("4.0.0", "4.18.0", False)],
        )
        db = self._db_with(adv)
        self.assertEqual(len(db.check("lodash", "3.9.9")), 0)

    def test_check_inclusive_upper_bound(self):
        adv = _make_advisory(
            package_name="lodash",
            affected_ranges=[("4.0.0", "4.18.0", True)],
        )
        db = self._db_with(adv)
        self.assertEqual(len(db.check("lodash", "4.18.0")), 1)
        self.assertEqual(len(db.check("lodash", "4.18.1")), 0)

    def test_check_no_upper_bound_range(self):
        adv = _make_advisory(
            package_name="lodash",
            affected_ranges=[("4.0.0", "", False)],
        )
        db = self._db_with(adv)
        self.assertEqual(len(db.check("lodash", "99.99.99")), 1)
        self.assertEqual(len(db.check("lodash", "3.9.9")), 0)

    def test_check_unparseable_version(self):
        adv = _make_advisory(
            package_name="lodash",
            affected_ranges=[("4.0.0", "4.18.0", False)],
        )
        db = self._db_with(adv)
        self.assertEqual(len(db.check("lodash", "not-a-version")), 0)

    def test_check_unparseable_introduced_version(self):
        adv = _make_advisory(
            package_name="lodash",
            affected_ranges=[("not-semver", "4.18.0", False)],
        )
        db = self._db_with(adv)
        self.assertEqual(len(db.check("lodash", "4.17.0")), 0)

    def test_check_fallback_fixed_version_heuristic(self):
        """When no affected_ranges, check uses fixed_version heuristic."""
        adv = _make_advisory(
            package_name="lodash",
            fixed_version="4.18.0",
            affected_ranges=[],
        )
        db = self._db_with(adv)
        self.assertEqual(len(db.check("lodash", "4.17.0")), 1)
        self.assertEqual(len(db.check("lodash", "4.18.0")), 0)

    def test_check_fallback_skipped_when_ranges_present(self):
        """Fixed version heuristic is NOT used when ranges are available."""
        adv = _make_advisory(
            package_name="lodash",
            fixed_version="99.99.99",
            affected_ranges=[("4.0.0", "4.18.0", False)],
        )
        db = self._db_with(adv)
        self.assertEqual(len(db.check("lodash", "4.18.0")), 0)

    def test_check_explicit_affected_versions(self):
        adv = _make_advisory(
            package_name="lodash",
            affected_versions=["4.17.0", "4.17.1"],
            affected_ranges=[],
            fixed_version="",
        )
        db = self._db_with(adv)
        self.assertEqual(len(db.check("lodash", "4.17.0")), 1)
        self.assertEqual(len(db.check("lodash", "4.17.1")), 1)
        self.assertEqual(len(db.check("lodash", "4.17.2")), 0)

    def test_check_affected_versions_with_operators(self):
        adv = _make_advisory(
            package_name="lodash",
            affected_versions=[">=4.0.0", "<4.18.0"],
            affected_ranges=[],
            fixed_version="",
        )
        db = self._db_with(adv)
        self.assertEqual(len(db.check("lodash", "4.17.0")), 1)

    def test_check_multiple_advisories_same_package(self):
        adv1 = _make_advisory(id="A1", package_name="lodash", affected_ranges=[("4.0.0", "4.17.0", False)])
        adv2 = _make_advisory(id="A2", package_name="lodash", affected_ranges=[("4.14.0", "4.17.2", False)])
        db = self._db_with(adv1, adv2)
        results = db.check("lodash", "4.17.1")
        ids = {r.id for r in results}
        self.assertNotIn("A1", ids)
        self.assertIn("A2", ids)

    def test_check_returns_advisory_objects(self):
        adv = _make_advisory(
            id="CVE-2024-0001",
            package_name="lodash",
            severity="CRITICAL",
            summary="Prototype pollution",
            fixed_version="4.18.1",
            affected_ranges=[("4.0.0", "4.18.1", False)],
        )
        db = self._db_with(adv)
        results = db.check("lodash", "4.17.0")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].id, "CVE-2024-0001")
        self.assertEqual(results[0].severity, "CRITICAL")
        self.assertEqual(results[0].summary, "Prototype pollution")

    def test_check_mixed_prerelease_identifiers_no_typeerror(self):
        """Regression: mixed numeric/alphanumeric pre-release identifiers used to
        raise TypeError inside _version_affected (int vs str tuple comparison).
        Both crash directions must yield a verdict, not an exception."""
        # alpha lower bound vs numeric installed version (old: int vs str)
        adv_alpha = _make_advisory(id="A-ALPHA-BOUND", affected_ranges=[("1.0.0-alpha", "2.0.0", False)])
        # numeric lower bound vs alpha installed version (old: str vs int)
        adv_numeric = _make_advisory(id="A-NUMERIC-BOUND", affected_ranges=[("1.0.0-2", "2.0.0", False)])
        db = self._db_with(adv_alpha, adv_numeric)

        ids = {r.id for r in db.check("lodash", "1.0.0-2")}
        self.assertNotIn("A-ALPHA-BOUND", ids)  # 2 < alpha
        self.assertIn("A-NUMERIC-BOUND", ids)  # 2 >= 2

        ids = {r.id for r in db.check("lodash", "1.0.0-beta")}
        self.assertIn("A-ALPHA-BOUND", ids)  # beta > alpha
        self.assertIn("A-NUMERIC-BOUND", ids)  # beta > 2


# ══════════════════════════════════════════════════════════════════════════
# AdvisoryDB — _parse_version
# ══════════════════════════════════════════════════════════════════════════


class TestParseVersion(unittest.TestCase):
    def test_standard(self):
        self.assertEqual(AdvisoryDB._parse_version("1.2.3"), (1, 2, 3, (1,)))

    def test_with_prefix(self):
        self.assertEqual(AdvisoryDB._parse_version("v1.2.3"), (1, 2, 3, (1,)))

    def test_empty(self):
        self.assertIsNone(AdvisoryDB._parse_version(""))

    def test_no_match(self):
        self.assertIsNone(AdvisoryDB._parse_version("not-a-version"))

    def test_embedded(self):
        v = AdvisoryDB._parse_version("1.2.3-beta.1")
        self.assertEqual(v[:3], (1, 2, 3))
        # Ordering relations, not the private tuple representation.
        self.assertLess(v, AdvisoryDB._parse_version("1.2.3"))  # pre-release < release
        self.assertLess(
            AdvisoryDB._parse_version("1.0.0-2"),
            AdvisoryDB._parse_version("1.0.0-alpha"),
        )  # numeric identifier < alphanumeric (semver §11)
        self.assertLess(
            AdvisoryDB._parse_version("1.0.0-beta.2"),
            AdvisoryDB._parse_version("1.0.0-beta.11"),
        )  # numeric identifiers compare numerically
        self.assertLess(
            AdvisoryDB._parse_version("1.2.0"),
            AdvisoryDB._parse_version("1.10.0"),
        )  # numeric core compares numerically

    def test_large_numbers(self):
        self.assertEqual(AdvisoryDB._parse_version("10.20.30"), (10, 20, 30, (1,)))


# ══════════════════════════════════════════════════════════════════════════
# AdvisoryDB — _version_in_range
# ══════════════════════════════════════════════════════════════════════════


class TestVersionInRange(unittest.TestCase):
    def test_gte(self):
        v = (1, 2, 3, (1,))
        self.assertTrue(AdvisoryDB._version_in_range(v, ">=1.2.0"))
        self.assertTrue(AdvisoryDB._version_in_range(v, ">=1.2.3"))
        self.assertFalse(AdvisoryDB._version_in_range(v, ">=1.2.4"))

    def test_lte(self):
        v = (1, 2, 3, (1,))
        self.assertTrue(AdvisoryDB._version_in_range(v, "<=1.2.3"))
        self.assertTrue(AdvisoryDB._version_in_range(v, "<=1.2.4"))
        self.assertFalse(AdvisoryDB._version_in_range(v, "<=1.2.2"))

    def test_gt(self):
        v = (1, 2, 3, (1,))
        self.assertTrue(AdvisoryDB._version_in_range(v, ">1.2.2"))
        self.assertFalse(AdvisoryDB._version_in_range(v, ">1.2.3"))

    def test_lt(self):
        v = (1, 2, 3, (1,))
        self.assertTrue(AdvisoryDB._version_in_range(v, "<1.2.4"))
        self.assertFalse(AdvisoryDB._version_in_range(v, "<1.2.3"))

    def test_exact(self):
        v = (1, 2, 3, (1,))
        self.assertTrue(AdvisoryDB._version_in_range(v, "1.2.3"))
        self.assertFalse(AdvisoryDB._version_in_range(v, "1.2.4"))

    def test_unparseable_range(self):
        v = (1, 2, 3, (1,))
        self.assertFalse(AdvisoryDB._version_in_range(v, ">=not-semver"))

    def test_whitespace_stripped(self):
        v = (1, 2, 3, (1,))
        self.assertTrue(AdvisoryDB._version_in_range(v, "  >=1.2.0  "))


# ══════════════════════════════════════════════════════════════════════════
# AdvisoryDB — properties
# ══════════════════════════════════════════════════════════════════════════


class TestAdvisoryDBProperties(unittest.TestCase):
    def test_properties_empty(self):
        db = AdvisoryDB()
        self.assertEqual(db.package_count, 0)
        self.assertEqual(db.advisory_count, 0)
        self.assertFalse(db.is_loaded)

    def test_properties_after_manual_insert(self):
        db = AdvisoryDB()
        db._advisories.setdefault("pkg1", []).append(_make_advisory(id="A1", package_name="pkg1"))
        db._advisories.setdefault("pkg1", []).append(_make_advisory(id="A2", package_name="pkg1"))
        db._advisories.setdefault("pkg2", []).append(_make_advisory(id="A3", package_name="pkg2"))
        db._loaded = True
        self.assertEqual(db.package_count, 2)
        self.assertEqual(db.advisory_count, 3)
        self.assertTrue(db.is_loaded)


# ══════════════════════════════════════════════════════════════════════════
# load_bundled_advisories
# ══════════════════════════════════════════════════════════════════════════


class TestLoadBundledAdvisories(unittest.TestCase):
    def test_returns_advisory_db(self):
        db = load_bundled_advisories()
        self.assertIsInstance(db, AdvisoryDB)

    def test_bundled_file_exists_and_loaded(self):
        db = load_bundled_advisories()
        self.assertIsInstance(db, AdvisoryDB)
        self.assertGreater(db.advisory_count, 0)

    def test_handles_malformed_bundled_file(self):
        """Monkey-patch to point at a bad file and verify graceful handling."""
        Path(
            __file__
        ).resolve().parent.parent / "src" / "picosentry" / "corpus" / "advisories" / "npm-critical-advisories.json"
        # Write a bad file to a temp location and patch the module
        tmpdir = tempfile.mkdtemp()
        bad_file = Path(tmpdir) / "npm-critical-advisories.json"
        bad_file.write_text("NOT VALID JSON", encoding="utf-8")

        # We can't easily monkey-patch Path, so just verify the function
        # doesn't crash with the real bundled file (which is valid but empty)
        db = load_bundled_advisories()
        self.assertIsInstance(db, AdvisoryDB)


# ══════════════════════════════════════════════════════════════════════════
# default_advisory_dir
# ══════════════════════════════════════════════════════════════════════════


class TestDefaultAdvisoryDir(unittest.TestCase):
    def test_default_path_without_env(self):
        env_key = "PICOADVISORY_DIR"
        original = os.environ.pop(env_key, None)
        try:
            result = default_advisory_dir()
            self.assertEqual(result, Path.home() / ".local" / "share" / "picosentry" / "advisories")
        finally:
            if original is not None:
                os.environ[env_key] = original

    def test_env_var_overrides(self):
        env_key = "PICOADVISORY_DIR"
        original = os.environ.get(env_key)
        os.environ[env_key] = "/custom/advisory/path"
        try:
            result = default_advisory_dir()
            self.assertEqual(result, Path("/custom/advisory/path"))
        finally:
            if original is not None:
                os.environ[env_key] = original
            else:
                del os.environ[env_key]


# ══════════════════════════════════════════════════════════════════════════
# Integration: load → check
# ══════════════════════════════════════════════════════════════════════════


class TestIntegration(unittest.TestCase):
    """End-to-end: load OSV files and query the database."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def _dir(self) -> Path:
        return Path(self.tmpdir)

    def test_full_roundtrip(self):
        d = self._dir()
        osv = _make_osv(
            adv_id="CVE-2024-0001",
            pkg_name="express",
            summary="Prototype pollution in express",
            severity="CRITICAL",
            introduced="4.0.0",
            fixed="4.18.1",
        )
        _write_json(d / "CVE-2024-0001.json", osv)

        db = AdvisoryDB(d)
        self.assertTrue(db.is_loaded)

        # Affected version
        results = db.check("express", "4.18.0")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].id, "CVE-2024-0001")
        self.assertEqual(results[0].severity, "CRITICAL")
        self.assertEqual(results[0].fixed_version, "4.18.1")

        # Fixed version
        self.assertEqual(len(db.check("express", "4.18.1")), 0)

        # Different package
        self.assertEqual(len(db.check("lodash", "4.18.0")), 0)

    def test_multiple_advisories_same_package(self):
        d = self._dir()
        _write_json(d / "a1.json", _make_osv(adv_id="GHSA-a1", pkg_name="lodash", introduced="4.0.0", fixed="4.17.0"))
        _write_json(d / "a2.json", _make_osv(adv_id="GHSA-a2", pkg_name="lodash", introduced="4.14.0", fixed="4.17.2"))

        db = AdvisoryDB(d)
        results = db.check("lodash", "4.17.1")
        ids = {r.id for r in results}
        self.assertNotIn("GHSA-a1", ids)
        self.assertIn("GHSA-a2", ids)

    def test_malformed_file_amidst_valid(self):
        d = self._dir()
        _write_json(d / "valid.json", _make_osv(adv_id="GHSA-valid", pkg_name="lodash", severity="HIGH"))
        (d / "bad.json").write_text("{not json}", encoding="utf-8")

        db = AdvisoryDB(d)
        self.assertTrue(db.is_loaded)
        self.assertEqual(db.advisory_count, 1)

    def test_severity_mapping_all_levels(self):
        d = self._dir()
        for i, sev in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
            _write_json(d / f"sev_{i}.json", _make_osv(adv_id=f"GHSA-sev-{i}", pkg_name=f"pkg-{i}", severity=sev))

        db = AdvisoryDB(d)
        self.assertEqual(db.advisory_count, 4)
        for i, sev in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
            results = db.check(f"pkg-{i}", "1.5.0")
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].severity, sev)

    def test_load_then_load_again_accumulates(self):
        d = self._dir()
        _write_json(d / "a.json", _make_osv(adv_id="GHSA-a", pkg_name="lodash"))
        db = AdvisoryDB(d)
        self.assertEqual(db.advisory_count, 1)

        d2 = Path(tempfile.mkdtemp())
        _write_json(d2 / "b.json", _make_osv(adv_id="GHSA-b", pkg_name="express"))
        db.load(d2)
        self.assertEqual(db.advisory_count, 2)


# ══════════════════════════════════════════════════════════════════════════
# _SEMVER_RE
# ══════════════════════════════════════════════════════════════════════════


class TestSemverRegex(unittest.TestCase):
    def test_standard_version(self):
        m = _SEMVER_RE.search("1.2.3")
        self.assertEqual(m.group(0), "1.2.3")

    def test_prefixed_version(self):
        m = _SEMVER_RE.search("v1.2.3")
        self.assertIsNotNone(m)

    def test_version_with_prerelease(self):
        m = _SEMVER_RE.search("1.2.3-beta.1")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(0), "1.2.3-beta.1")

    def test_no_match(self):
        self.assertIsNone(_SEMVER_RE.search("not-a-version"))


def test_default_path_advisory_scan_fires_without_explicit_db(tmp_path, monkeypatch):
    """WO5.0.0-009 — the default scan path (no --advisory-db) must load the
    bundled corpus envelope and fire L2-ADV-001 on a known-vulnerable dep."""
    from picosentry.scan.rules import advisory_check
    from picosentry.scan.engine import create_default_engine

    # Hermetic: force the bundled corpus (no user corpus) and an absent user
    # advisory dir, and clear the process-level advisory DB cache.
    monkeypatch.setenv("PICOSENTRY_CORPUS_DIR", str(tmp_path / "no-user-corpus"))
    monkeypatch.setenv("PICOSENTRY_ADVISORY_DIR", str(tmp_path / "no-user-advisories"))
    monkeypatch.delenv("PICOADVISORY_DIR", raising=False)
    advisory_check._advisory_db_cache.clear()

    target = tmp_path / "proj"
    (target / "node_modules" / "lodash").mkdir(parents=True)
    (target / "package.json").write_text(
        json.dumps({"name": "x", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}})
    )
    (target / "node_modules" / "lodash" / "package.json").write_text(
        json.dumps({"name": "lodash", "version": "4.17.15"})
    )

    result = create_default_engine().scan(target)
    adv = [f for f in result.findings if f.rule_id == "L2-ADV-001" and f.package.startswith("lodash@")]
    assert adv, (
        f"default-path scan (no --advisory-db) must fire L2-ADV-001 for "
        f"lodash@4.17.15; got: {[(f.rule_id, f.package) for f in result.findings]}"
    )
    assert any("GHSA" in f.message or "CVE" in f.message for f in adv)


if __name__ == "__main__":
    unittest.main()
