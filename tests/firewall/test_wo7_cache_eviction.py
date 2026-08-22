"""WO7-010 — VerdictCache O(n) eviction on every get/put.

``_evict_expired`` iterated ALL entries on every ``get``/``put`` — 3.4ms
at 10k entries. Lazy eviction (expire-in-place on read of a stale entry)
makes ``get``/``put`` O(1) amortized; ``stats`` keeps the full scan as a
cold path.
"""

from __future__ import annotations

import time

from picosentry.firewall.cache import VerdictCache
from picosentry.firewall.scanner import FirewallVerdict


class TestCacheLazyEviction:
    def test_expired_entry_evicted_on_read(self, monkeypatch):
        now = [0.0]
        monkeypatch.setattr("picosentry.firewall.cache.time.monotonic", lambda: now[-1])
        cache = VerdictCache(ttl_seconds=1, max_entries=100)
        cache.put("npm", "old", "1", FirewallVerdict.ALLOW)
        assert cache.get("npm", "old", "1") == FirewallVerdict.ALLOW
        now.append(2.0)
        assert cache.get("npm", "old", "1") is None

    def test_expired_entry_not_in_stats(self, monkeypatch):
        now = [0.0]
        monkeypatch.setattr("picosentry.firewall.cache.time.monotonic", lambda: now[-1])
        cache = VerdictCache(ttl_seconds=1, max_entries=100)
        cache.put("npm", "a", "1", FirewallVerdict.ALLOW)
        cache.put("npm", "b", "1", FirewallVerdict.BLOCK)
        now.append(2.0)
        stats = cache.stats()
        assert stats.size == 0, "stats() should evict expired entries on the cold path"

    def test_get_put_perf_at_10k_entries(self):
        cache = VerdictCache(ttl_seconds=3600, max_entries=20_000)
        for i in range(10_000):
            cache.put("npm", f"pkg{i}", "1.0", FirewallVerdict.ALLOW)

        start = time.perf_counter()
        for i in range(1000):
            cache.get("npm", f"pkg{i}", "1.0")
        elapsed_get = time.perf_counter() - start

        start = time.perf_counter()
        for i in range(10_000, 11_000):
            cache.put("npm", f"pkg{i}", "1.0", FirewallVerdict.ALLOW)
        elapsed_put = time.perf_counter() - start

        p99_get = elapsed_get / 1000 * 1000
        p99_put = elapsed_put / 1000 * 1000
        assert p99_get < 0.5, f"get p99 {p99_get:.3f}ms exceeds 0.5ms budget at 10k entries"
        assert p99_put < 0.5, f"put p99 {p99_put:.3f}ms exceeds 0.5ms budget at 10k entries"

    def test_no_full_scan_on_get(self, monkeypatch):
        now = [0.0]
        monkeypatch.setattr("picosentry.firewall.cache.time.monotonic", lambda: now[-1])
        cache = VerdictCache(ttl_seconds=3600, max_entries=100_000)
        for i in range(5000):
            cache.put("npm", f"pkg{i}", "1", FirewallVerdict.ALLOW)

        now.append(0.001)

        call_count = [0]
        original_evict = cache._evict_expired

        def counting_evict():
            call_count[0] += 1
            original_evict()

        cache._evict_expired = counting_evict
        cache.get("npm", "pkg0", "1")
        assert call_count[0] == 0, "get() must not trigger full-scan _evict_expired"

    def test_no_full_scan_on_put(self, monkeypatch):
        now = [0.0]
        monkeypatch.setattr("picosentry.firewall.cache.time.monotonic", lambda: now[-1])
        cache = VerdictCache(ttl_seconds=3600, max_entries=100_000)
        for i in range(5000):
            cache.put("npm", f"pkg{i}", "1", FirewallVerdict.ALLOW)

        call_count = [0]
        original_evict = cache._evict_expired

        def counting_evict():
            call_count[0] += 1
            original_evict()

        cache._evict_expired = counting_evict
        cache.put("npm", "newpkg", "1", FirewallVerdict.BLOCK)
        assert call_count[0] == 0, "put() must not trigger full-scan _evict_expired"
