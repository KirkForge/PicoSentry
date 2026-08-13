from __future__ import annotations

import time

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

    def test_ttl_expiration(self):
        cache = VerdictCache(ttl_seconds=1)
        cache.put("npm", "lodash", "4.17.21", FirewallVerdict.BLOCK)
        assert cache.get("npm", "lodash", "4.17.21") == FirewallVerdict.BLOCK
        time.sleep(1.1)
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
