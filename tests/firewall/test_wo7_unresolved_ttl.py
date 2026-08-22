"""WO7-009 — UNRESOLVED verdict cached with full TTL.

A version that returned UNRESOLVED at T0 and is published at T1 (cache
advanced past the short TTL) must be re-resolved and allowed; the full-TTL
path is gone.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from picosentry.firewall.scanner import FirewallScanner, FirewallVerdict


class TestUnresolvedShortTtl:
    def test_unresolved_uses_short_ttl_not_full(self, monkeypatch):
        now = [0.0]
        monkeypatch.setattr("picosentry.firewall.cache.time.monotonic", lambda: now[-1])

        scanner = FirewallScanner(cache_ttl_seconds=3600)
        catalog = {"name": "acme-lib", "versions": {"1.0.0": {"version": "1.0.0"}}}

        v1, _ = scanner.scan_metadata("npm", "acme-lib", "9.9.9", catalog)
        assert v1 == FirewallVerdict.UNRESOLVED

        cached = scanner.cache.get("npm", "acme-lib", "9.9.9")
        assert cached is not None
        assert cached[0] == FirewallVerdict.UNRESOLVED

        now.append(31.0)
        cached = scanner.cache.get("npm", "acme-lib", "9.9.9")
        assert cached is None, "UNRESOLVED must expire after short TTL (30s), not full TTL (3600s)"

    def test_unresolved_re_resolved_after_short_ttl_expires(self, monkeypatch):
        now = [0.0]
        monkeypatch.setattr("picosentry.firewall.cache.time.monotonic", lambda: now[-1])

        scanner = FirewallScanner(cache_ttl_seconds=3600)

        catalog_missing = {"name": "fresh-pkg", "versions": {"1.0.0": {"version": "1.0.0"}}}
        v1, _ = scanner.scan_metadata("npm", "fresh-pkg", "2.0.0", catalog_missing)
        assert v1 == FirewallVerdict.UNRESOLVED

        now.append(31.0)

        catalog_published = {
            "name": "fresh-pkg",
            "dist-tags": {"latest": "2.0.0"},
            "versions": {"2.0.0": {"name": "fresh-pkg", "version": "2.0.0", "license": "MIT"}},
        }
        v2, _ = scanner.scan_metadata("npm", "fresh-pkg", "2.0.0", catalog_published)
        assert v2 == FirewallVerdict.ALLOW, "after short TTL expires, a newly-published version must be re-resolved"

    def test_allow_uses_full_ttl(self, monkeypatch):
        now = [0.0]
        monkeypatch.setattr("picosentry.firewall.cache.time.monotonic", lambda: now[-1])

        scanner = FirewallScanner(cache_ttl_seconds=3600)
        manifest = {"name": "allow-pkg", "version": "1.0.0"}
        with patch.object(scanner, "_get_engine") as mock_engine:
            mock_result = MagicMock()
            mock_result.findings = []
            mock_engine.return_value.scan.return_value = mock_result
            v1, _ = scanner.scan_metadata("npm", "allow-pkg", "1.0.0", manifest)
            assert v1 == FirewallVerdict.ALLOW

            now.append(100.0)
            cached = scanner.cache.get("npm", "allow-pkg", "1.0.0")
            assert cached is not None, "ALLOW must use full TTL (3600s), not short TTL"
            assert cached[0] == FirewallVerdict.ALLOW
