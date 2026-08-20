from __future__ import annotations

import threading

from picosentry.firewall.cache import VerdictCache
from picosentry.firewall.scanner import FirewallVerdict


class TestVerdictCache:
    def test_put_and_get(self):
        cache = VerdictCache(ttl_seconds=60)
        cache.put("npm", "express", "4.18.0", FirewallVerdict.ALLOW)
        assert cache.get("npm", "express", "4.18.0") == FirewallVerdict.ALLOW

    def test_get_miss(self):
        cache = VerdictCache(ttl_seconds=60)
        assert cache.get("npm", "express", "4.18.0") is None

    def test_ttl_expiration(self, monkeypatch):
        now = [0.0]
        monkeypatch.setattr("picosentry.firewall.cache.time.monotonic", lambda: now[-1])

        cache = VerdictCache(ttl_seconds=1)
        cache.put("npm", "lodash", "4.17.21", FirewallVerdict.BLOCK)
        assert cache.get("npm", "lodash", "4.17.21") == FirewallVerdict.BLOCK
        now.append(2.0)
        assert cache.get("npm", "lodash", "4.17.21") is None

    def test_clear(self):
        cache = VerdictCache(ttl_seconds=60)
        cache.put("npm", "express", "4.18.0", FirewallVerdict.ALLOW)
        cache.clear()
        assert cache.get("npm", "express", "4.18.0") is None

    def test_stats(self):
        cache = VerdictCache(ttl_seconds=60)
        cache.put("npm", "express", "4.18.0", FirewallVerdict.ALLOW)
        cache.get("npm", "express", "4.18.0")
        cache.get("npm", "missing", "1.0.0")
        stats = cache.stats()
        assert stats.hits == 1
        assert stats.misses == 1
        assert stats.size == 1

    def test_different_ecosystems(self):
        cache = VerdictCache(ttl_seconds=60)
        cache.put("npm", "express", "4.18.0", FirewallVerdict.ALLOW)
        cache.put("pypi", "requests", "2.31.0", FirewallVerdict.BLOCK)
        assert cache.get("npm", "express", "4.18.0") == FirewallVerdict.ALLOW
        assert cache.get("pypi", "requests", "2.31.0") == FirewallVerdict.BLOCK
        assert cache.get("npm", "requests", "2.31.0") is None

    def test_overwrite(self):
        cache = VerdictCache(ttl_seconds=60)
        cache.put("npm", "express", "4.18.0", FirewallVerdict.ALLOW)
        cache.put("npm", "express", "4.18.0", FirewallVerdict.BLOCK)
        assert cache.get("npm", "express", "4.18.0") == FirewallVerdict.BLOCK

    def test_max_entries_evicts_soonest_expiry(self):
        cache = VerdictCache(ttl_seconds=60, max_entries=2)
        cache.put("npm", "a", "1", FirewallVerdict.ALLOW)
        cache.put("npm", "b", "1", FirewallVerdict.ALLOW)
        cache.put("npm", "c", "1", FirewallVerdict.BLOCK)
        assert cache.get("npm", "a", "1") is None
        assert cache.get("npm", "b", "1") == FirewallVerdict.ALLOW
        assert cache.get("npm", "c", "1") == FirewallVerdict.BLOCK
        assert cache.stats().size == 2


class TestVerdictCacheConcurrency:
    # WO6-017: VerdictCache serves ThreadingHTTPServer's one-thread-per-request
    # model. 8 threads x 3000 mixed get/put/clear/stats ops must complete with
    # zero RuntimeError (dict changed size during iteration) and zero KeyError
    # (evicted-between-get-and-del). Tight TTL + small max_entries force the
    # eviction and expiry races that the unsynchronized cache used to lose.

    def test_concurrent_get_put_evict_zero_errors(self, monkeypatch):
        cache = VerdictCache(ttl_seconds=2, max_entries=50)
        errors: list[BaseException] = []

        def worker():
            try:
                for i in range(3000):
                    key = f"pkg{i % 200}"
                    cache.put("npm", key, "1", FirewallVerdict.ALLOW)
                    cache.get("npm", key, "1")
                    if i % 500 == 0:
                        cache.stats()
                        cache.clear()
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, f"concurrent cache ops raised: {errors!r}"

    def test_concurrent_stats_during_mutation_no_error(self):
        cache = VerdictCache(ttl_seconds=1, max_entries=10)
        errors: list[BaseException] = []

        def mutator():
            try:
                for i in range(3000):
                    cache.put("npm", f"k{i % 20}", "1", FirewallVerdict.ALLOW)
            except BaseException as exc:
                errors.append(exc)

        def reader():
            try:
                for _ in range(3000):
                    cache.stats()
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=mutator)] + [threading.Thread(target=reader) for _ in range(7)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, f"stats during mutation raised: {errors!r}"
