"""
test_license.py — Tests for L2-LICENSE-001 license compliance detection.

Deterministic: same input + same corpus = same output. Always.
"""

import json
from pathlib import Path

import pytest

from picosentry.scan.engine import create_default_engine
from picosentry.scan.rules.license import detect_license_issues


@pytest.fixture
def corpus_dir():
    """Use built-in corpus directory."""
    return Path(__file__).parent.parent / "src" / "scanner" / "corpus"


class TestNoLicenseField:
    """Packages missing the license field entirely."""

    def test_no_license_field(self, tmp_path, corpus_dir):
        """Package with no license field → MEDIUM finding."""
        pkg = {"name": "no-license-pkg", "version": "1.0.0"}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        findings = detect_license_issues(tmp_path)
        assert len(findings) == 1
        assert findings[0].rule_id == "L2-LICENSE-001"
        assert findings[0].severity.value == "MEDIUM"
        assert "no license field" in findings[0].message.lower()

    def test_empty_license_field(self, tmp_path, corpus_dir):
        """Package with empty string license → unknown finding."""
        pkg = {"name": "empty-license", "version": "1.0.0", "license": ""}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        findings = detect_license_issues(tmp_path)
        assert len(findings) == 1
        assert findings[0].rule_id == "L2-LICENSE-001"


class TestUnlicensedPackages:
    """Packages explicitly marked as UNLICENSED."""

    def test_unlicensed_string(self, tmp_path, corpus_dir):
        """UNLICENSED license → HIGH finding."""
        pkg = {"name": "proprietary-lib", "version": "2.0.0", "license": "UNLICENSED"}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        findings = detect_license_issues(tmp_path)
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"
        assert "UNLICENSED" in findings[0].message

    def test_see_license_in(self, tmp_path, corpus_dir):
        """'SEE LICENSE IN' license → HIGH finding."""
        pkg = {"name": "see-license", "version": "1.0.0", "license": "SEE LICENSE IN LICENSE"}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        findings = detect_license_issues(tmp_path)
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"


class TestCopyleftLicenses:
    """Packages with copyleft (GPL, AGPL) licenses."""

    def test_gpl_3(self, tmp_path, corpus_dir):
        """GPL-3.0 → MEDIUM copyleft finding."""
        pkg = {"name": "gpl-lib", "version": "1.0.0", "license": "GPL-3.0"}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        findings = detect_license_issues(tmp_path)
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"
        assert "copyleft" in findings[0].message.lower()

    def test_agpl_3(self, tmp_path, corpus_dir):
        """AGPL-3.0 → MEDIUM copyleft finding."""
        pkg = {"name": "agpl-lib", "version": "1.0.0", "license": "AGPL-3.0"}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        findings = detect_license_issues(tmp_path)
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_gpl_2_or_later(self, tmp_path, corpus_dir):
        """GPL-2.0-or-later → MEDIUM copyleft finding."""
        pkg = {"name": "gpl2-lib", "version": "1.0.0", "license": "GPL-2.0-or-later"}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        findings = detect_license_issues(tmp_path)
        assert len(findings) == 1
        assert "copyleft" in findings[0].message.lower()

    def test_lgpl(self, tmp_path, corpus_dir):
        """LGPL-2.1 → MEDIUM copyleft finding."""
        pkg = {"name": "lgpl-lib", "version": "1.0.0", "license": "LGPL-2.1"}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        findings = detect_license_issues(tmp_path)
        assert len(findings) == 1
        assert "copyleft" in findings[0].message.lower()


class TestPermissiveLicenses:
    """Packages with permissive licenses should produce NO findings."""

    def test_mit_license(self, tmp_path, corpus_dir):
        """MIT license → no finding."""
        pkg = {"name": "mit-lib", "version": "1.0.0", "license": "MIT"}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        findings = detect_license_issues(tmp_path)
        assert len(findings) == 0

    def test_apache_2(self, tmp_path, corpus_dir):
        """Apache-2.0 → no finding."""
        pkg = {"name": "apache-lib", "version": "1.0.0", "license": "Apache-2.0"}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        findings = detect_license_issues(tmp_path)
        assert len(findings) == 0

    def test_bsd_3_clause(self, tmp_path, corpus_dir):
        """BSD-3-Clause → no finding."""
        pkg = {"name": "bsd-lib", "version": "1.0.0", "license": "BSD-3-Clause"}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        findings = detect_license_issues(tmp_path)
        assert len(findings) == 0

    def test_isc_license(self, tmp_path, corpus_dir):
        """ISC → no finding."""
        pkg = {"name": "isc-lib", "version": "1.0.0", "license": "ISC"}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        findings = detect_license_issues(tmp_path)
        assert len(findings) == 0

    def test_dual_mit_or_apache(self, tmp_path, corpus_dir):
        """(MIT OR Apache-2.0) dual license → no finding."""
        pkg = {"name": "dual-lib", "version": "1.0.0", "license": "(MIT OR Apache-2.0)"}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        findings = detect_license_issues(tmp_path)
        assert len(findings) == 0

    def test_unlicense(self, tmp_path, corpus_dir):
        """Unlicense (public domain) → no finding."""
        pkg = {"name": "unlicense-lib", "version": "1.0.0", "license": "Unlicense"}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        findings = detect_license_issues(tmp_path)
        assert len(findings) == 0


class TestUnknownLicenses:
    """Packages with unrecognized license strings."""

    def test_unknown_license_string(self, tmp_path, corpus_dir):
        """Custom/unknown license string → LOW finding."""
        pkg = {"name": "weird-license", "version": "1.0.0", "license": "MyCustomLicense2024"}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        findings = detect_license_issues(tmp_path)
        assert len(findings) == 1
        assert findings[0].severity.value == "LOW"
        assert "unrecognized" in findings[0].message.lower()


class TestLicenseObjectType:
    """npm supports license as an object with 'type' field."""

    def test_license_object_type(self, tmp_path, corpus_dir):
        """License as {"type": "MIT"} → no finding."""
        pkg = {
            "name": "obj-license",
            "version": "1.0.0",
            "license": {"type": "MIT", "url": "https://opensource.org/licenses/MIT"},
        }
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        findings = detect_license_issues(tmp_path)
        assert len(findings) == 0

    def test_license_object_gpl(self, tmp_path, corpus_dir):
        """License as {"type": "GPL-3.0"} → MEDIUM copyleft finding."""
        pkg = {"name": "obj-gpl", "version": "1.0.0", "license": {"type": "GPL-3.0"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        findings = detect_license_issues(tmp_path)
        assert len(findings) == 1
        assert "copyleft" in findings[0].message.lower()


class TestNodeModulesScanning:
    """License scanning in node_modules dependencies."""

    def test_scan_node_modules(self, tmp_path, corpus_dir):
        """Scan license issues in node_modules packages."""
        root_pkg = {"name": "my-app", "version": "1.0.0", "license": "MIT"}
        (tmp_path / "package.json").write_text(json.dumps(root_pkg))

        nm = tmp_path / "node_modules"
        nm.mkdir()
        evil_dir = nm / "evil-no-license"
        evil_dir.mkdir()
        evil_pkg = {"name": "evil-no-license", "version": "1.0.0"}
        (evil_dir / "package.json").write_text(json.dumps(evil_pkg))

        findings = detect_license_issues(tmp_path)
        assert len(findings) == 1
        assert findings[0].package == "evil-no-license@1.0.0"
        assert findings[0].severity.value == "MEDIUM"

    def test_scan_scoped_packages(self, tmp_path, corpus_dir):
        """Scan license issues in @scoped packages."""
        root_pkg = {"name": "my-app", "version": "1.0.0", "license": "MIT"}
        (tmp_path / "package.json").write_text(json.dumps(root_pkg))

        nm = tmp_path / "node_modules"
        scope_dir = nm / "@evil"
        scope_dir.mkdir(parents=True)
        pkg_dir = scope_dir / "proprietary"
        pkg_dir.mkdir()
        pkg_json = {"name": "@evil/proprietary", "version": "1.0.0", "license": "UNLICENSED"}
        (pkg_dir / "package.json").write_text(json.dumps(pkg_json))

        findings = detect_license_issues(tmp_path)
        # Should find the @evil/proprietary UNLICENSED finding
        assert len(findings) >= 1
        unlicensed = [f for f in findings if "UNLICENSED" in f.message]
        assert len(unlicensed) == 1
        assert unlicensed[0].severity.value == "HIGH"


class TestDeterminism:
    """Same input + same corpus = same output. Always."""

    def test_license_findings_are_deterministic(self, tmp_path, corpus_dir):
        """Running license detection twice on the same input must produce identical results."""
        pkg = {"name": "gpl-lib", "version": "1.0.0", "license": "GPL-3.0"}
        (tmp_path / "package.json").write_text(json.dumps(pkg))

        findings_a = detect_license_issues(tmp_path)
        findings_b = detect_license_issues(tmp_path)

        assert len(findings_a) == len(findings_b)
        for a, b in zip(findings_a, findings_b, strict=False):
            assert a.sort_key() == b.sort_key()
            assert a.to_dict() == b.to_dict()


class TestIntegrationWithEngine:
    """Test that L2-LICENSE-001 integrates with the scan engine."""

    def test_license_rule_in_default_engine(self):
        """L2-LICENSE-001 should be registered in the default engine."""
        engine = create_default_engine()
        assert "L2-LICENSE-001" in engine.list_rules()

    def test_scan_with_no_license(self, tmp_path):
        """Full engine scan detects missing license."""
        pkg = {"name": "no-license-app", "version": "1.0.0"}
        (tmp_path / "package.json").write_text(json.dumps(pkg))

        engine = create_default_engine()
        result = engine.scan(tmp_path, rules=["L2-LICENSE-001"])
        license_findings = [f for f in result.findings if f.rule_id == "L2-LICENSE-001"]
        assert len(license_findings) == 1
