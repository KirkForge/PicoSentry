"""Extended tests for IoC detection rule — L2-IOC-001."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from picosentry.scan.models import Severity
from picosentry.scan.rules.ioc_detection import (
    _check_package_against_iocs,
    _semver_matches,
    detect_custom_iocs,
)


class TestSemverMatches(unittest.TestCase):
    """Test _semver_matches version constraint logic."""

    def test_exact_match(self):
        self.assertTrue(_semver_matches("1.2.3", "1.2.3"))

    def test_exact_mismatch(self):
        self.assertFalse(_semver_matches("1.2.3", "1.2.4"))

    def test_caret_compatible(self):
        self.assertTrue(_semver_matches("1.5.0", "^1.2.0"))
        self.assertTrue(_semver_matches("1.2.9", "^1.2.0"))

    def test_caret_incompatible(self):
        self.assertFalse(_semver_matches("2.0.0", "^1.2.0"))

    def test_caret_zero_major(self):
        self.assertTrue(_semver_matches("0.3.5", "^0.3.0"))
        self.assertFalse(_semver_matches("0.4.0", "^0.3.0"))

    def test_caret_zero_zero(self):
        self.assertFalse(_semver_matches("0.0.5", "^0.0.4"))  # ^0.0.4 means >=0.0.4 <0.0.5
        self.assertFalse(_semver_matches("0.0.6", "^0.0.4"))

    def test_tilde_matches(self):
        self.assertTrue(_semver_matches("1.2.5", "~1.2.3"))
        self.assertFalse(_semver_matches("1.3.0", "~1.2.3"))

    def test_gte(self):
        self.assertTrue(_semver_matches("1.3.0", ">=1.2.0"))
        self.assertTrue(_semver_matches("1.2.0", ">=1.2.0"))
        self.assertFalse(_semver_matches("1.1.9", ">=1.2.0"))

    def test_lte(self):
        self.assertTrue(_semver_matches("1.1.0", "<=1.2.0"))
        self.assertTrue(_semver_matches("1.2.0", "<=1.2.0"))
        self.assertFalse(_semver_matches("1.2.1", "<=1.2.0"))

    def test_gt(self):
        self.assertTrue(_semver_matches("1.2.1", ">1.2.0"))
        self.assertFalse(_semver_matches("1.2.0", ">1.2.0"))

    def test_lt(self):
        self.assertTrue(_semver_matches("1.1.9", "<1.2.0"))
        self.assertFalse(_semver_matches("1.2.0", "<1.2.0"))

    def test_range(self):
        self.assertTrue(_semver_matches("1.5.0", "1.2.0 - 2.0.0"))
        self.assertFalse(_semver_matches("2.1.0", "1.2.0 - 2.0.0"))

    def test_wildcard(self):
        self.assertFalse(_semver_matches("99.99.99", "*"))  # wildcard * is handled by caller, not _semver_matches

    def test_v_prefix(self):
        self.assertTrue(_semver_matches("v1.2.3", "1.2.3"))

    def test_fallback_substring(self):
        self.assertTrue(_semver_matches("1.2.3", "1.2"))
        self.assertTrue(_semver_matches("1.2", "1.2.3"))

    def test_invalid_version(self):
        # Should fallback to substring match
        self.assertFalse(_semver_matches("notaversion", "1.2.3"))

    def test_two_part_version(self):
        self.assertTrue(_semver_matches("1.2", "^1.2"))


class TestCheckPackageAgainstIocs(unittest.TestCase):
    """Test per-package IoC checking."""

    def test_matching_ioc(self):
        iocs = [
            {
                "package_name": "evil-pkg",
                "version_range": "*",
                "severity": "HIGH",
                "name": "Evil Package",
                "description": "Known malicious",
                "id": "ioc-1",
            }
        ]
        findings = _check_package_against_iocs(
            "evil-pkg", "1.0.0", "evil-pkg@1.0.0", Path("/tmp/evil/package.json"), iocs
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "L2-IOC-001")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_no_matching_ioc(self):
        iocs = [
            {
                "package_name": "other-pkg",
                "version_range": "*",
                "severity": "HIGH",
                "name": "Other",
                "description": "test",
                "id": "ioc-2",
            }
        ]
        findings = _check_package_against_iocs(
            "clean-pkg", "1.0.0", "clean-pkg@1.0.0", Path("/tmp/clean/package.json"), iocs
        )
        self.assertEqual(len(findings), 0)

    def test_version_range_filter(self):
        iocs = [
            {
                "package_name": "pkg",
                "version_range": "^1.0.0",
                "severity": "HIGH",
                "name": "Vuln",
                "description": "test",
                "id": "ioc-3",
            }
        ]
        findings = _check_package_against_iocs("pkg", "1.5.0", "pkg@1.5.0", Path("/tmp/pkg/package.json"), iocs)
        self.assertEqual(len(findings), 1)

    def test_version_range_no_match(self):
        iocs = [
            {
                "package_name": "pkg",
                "version_range": "^2.0.0",
                "severity": "HIGH",
                "name": "Vuln",
                "description": "test",
                "id": "ioc-4",
            }
        ]
        findings = _check_package_against_iocs("pkg", "1.0.0", "pkg@1.0.0", Path("/tmp/pkg/package.json"), iocs)
        self.assertEqual(len(findings), 0)

    def test_invalid_severity_defaults_to_high(self):
        iocs = [
            {
                "package_name": "pkg",
                "version_range": "*",
                "severity": "UNKNOWN",
                "name": "Vuln",
                "description": "test",
                "id": "ioc-5",
            }
        ]
        findings = _check_package_against_iocs("pkg", "1.0.0", "pkg@1.0.0", Path("/tmp/pkg/package.json"), iocs)
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_ioc_with_references(self):
        iocs = [
            {
                "package_name": "pkg",
                "version_range": "*",
                "severity": "HIGH",
                "name": "Vuln",
                "description": "test",
                "id": "ioc-6",
                "references": ["https://example.com/advisory"],
            }
        ]
        findings = _check_package_against_iocs("pkg", "1.0.0", "pkg@1.0.0", Path("/tmp/pkg/package.json"), iocs)
        self.assertEqual(findings[0].references, ["https://example.com/advisory"])

    def test_empty_iocs(self):
        findings = _check_package_against_iocs("pkg", "1.0.0", "pkg@1.0.0", Path("/tmp/pkg/package.json"), [])
        self.assertEqual(len(findings), 0)

    def test_multiple_matching_iocs(self):
        iocs = [
            {
                "package_name": "pkg",
                "version_range": "*",
                "severity": "HIGH",
                "name": "V1",
                "description": "d1",
                "id": "ioc-a",
            },
            {
                "package_name": "pkg",
                "version_range": "*",
                "severity": "CRITICAL",
                "name": "V2",
                "description": "d2",
                "id": "ioc-b",
            },
        ]
        findings = _check_package_against_iocs("pkg", "1.0.0", "pkg@1.0.0", Path("/tmp/pkg/package.json"), iocs)
        self.assertEqual(len(findings), 2)


class TestDetectCustomIocs(unittest.TestCase):
    """Test full IoC detection scan."""

    @patch("picosentry.scan.rules.ioc_detection.load_all_iocs")
    def test_detect_with_iocs(self, mock_load):
        mock_load.return_value = [
            {
                "package_name": "evil",
                "version_range": "*",
                "severity": "CRITICAL",
                "name": "Evil Package",
                "description": "Malicious",
                "id": "ioc-e1",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            nm = Path(tmp) / "node_modules" / "evil"
            nm.mkdir(parents=True)
            (nm / "package.json").write_text(json.dumps({"name": "evil", "version": "1.0.0"}))
            findings = detect_custom_iocs(Path(tmp), Path(tmp) / "corpus")
            self.assertGreaterEqual(len(findings), 1)

    @patch("picosentry.scan.rules.ioc_detection.load_all_iocs")
    def test_detect_no_iocs(self, mock_load):
        mock_load.return_value = []
        with tempfile.TemporaryDirectory() as tmp:
            findings = detect_custom_iocs(Path(tmp), Path(tmp) / "corpus")
            self.assertEqual(len(findings), 0)

    @patch("picosentry.scan.rules.ioc_detection.load_all_iocs")
    def test_detect_load_error(self, mock_load):
        mock_load.side_effect = OSError("corrupted")
        with tempfile.TemporaryDirectory() as tmp:
            findings = detect_custom_iocs(Path(tmp), Path(tmp) / "corpus")
            self.assertEqual(len(findings), 0)

    @patch("picosentry.scan.rules.ioc_detection.load_all_iocs")
    def test_detect_root_package(self, mock_load):
        mock_load.return_value = [
            {
                "package_name": "root-pkg",
                "version_range": "*",
                "severity": "HIGH",
                "name": "Root Vuln",
                "description": "test",
                "id": "ioc-r1",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text(json.dumps({"name": "root-pkg", "version": "1.0.0"}))
            findings = detect_custom_iocs(Path(tmp), Path(tmp) / "corpus")
            self.assertGreaterEqual(len(findings), 1)

    @patch("picosentry.scan.rules.ioc_detection.load_all_iocs")
    def test_detect_nonexistent_target(self, mock_load):
        mock_load.return_value = []
        findings = detect_custom_iocs(Path("/nonexistent/path"), Path("/nonexistent/corpus"))
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
