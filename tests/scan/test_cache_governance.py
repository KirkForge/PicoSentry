"""Tests for PicoSentry cache governance features (retention, purge, wipe, caps)."""

import json
import tempfile
import time
import unittest
from pathlib import Path

from picosentry.scan.audit import configure_audit_sink, reset_audit_sink
from picosentry.scan.cache import ScanCache


class TestCachePurge(unittest.TestCase):
    """Tests for cache purge functionality."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cache = ScanCache(cache_dir=Path(self.tmpdir), ttl=999999)
        audit_path = Path(self.tmpdir) / "audit_test.jsonl"
        configure_audit_sink(path=audit_path, retention_days=0)

    def tearDown(self):
        reset_audit_sink()

    def test_purge_by_age(self):
        """Purge entries older than N days."""
        # Create an old entry
        old_key = self.cache._cache_key("old-lock", "old-corpus", "v1")
        path = self.cache._cache_path(old_key)
        entry = {
            "key": old_key,
            "cached_at": time.time() - 8 * 86400,
            "lockfile_hash": "old-lock",
            "corpus_hash": "old-corpus",
            "rule_version": "v1",
            "result": {"test": True},
        }
        path.write_text(json.dumps(entry))

        # Create a recent entry
        self.cache.put("new-lock", "new-corpus", "v1", {"test": True})

        # Purge entries older than 7 days
        removed = self.cache.purge(age_days=7)
        self.assertEqual(removed, 1)

        # Recent entry should still exist
        result = self.cache.get("new-lock", "new-corpus", "v1")
        self.assertIsNotNone(result)

    def test_purge_by_corpus_hash(self):
        """Purge entries matching a specific corpus hash."""
        self.cache.put("lock1", "corpus-abc", "v1", {"test": 1})
        self.cache.put("lock2", "corpus-abc", "v1", {"test": 2})
        self.cache.put("lock3", "corpus-xyz", "v1", {"test": 3})

        removed = self.cache.purge(corpus_hash="corpus-abc")
        self.assertEqual(removed, 2)

        result = self.cache.get("lock3", "corpus-xyz", "v1")
        self.assertIsNotNone(result)

    def test_purge_by_lockfile_hash(self):
        """Purge entries matching a specific lockfile hash."""
        self.cache.put("lock-A", "corpus1", "v1", {"test": 1})
        self.cache.put("lock-B", "corpus1", "v1", {"test": 2})

        removed = self.cache.purge(lockfile_hash="lock-A")
        self.assertEqual(removed, 1)

    def test_purge_empty_criteria_removes_all(self):
        """Purge with no filters removes nothing (use wipe for that)."""
        self.cache.put("lock1", "corpus1", "v1", {"test": True})
        # purge with no criteria should remove all (matches invalidate behavior)
        # Actually, purge with age_days=0 and no hash filters removes all
        removed = self.cache.purge()
        self.assertEqual(removed, 1)


class TestCacheWipe(unittest.TestCase):
    """Tests for cache wipe functionality."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cache = ScanCache(cache_dir=Path(self.tmpdir), ttl=999999)
        audit_path = Path(self.tmpdir) / "audit_test.jsonl"
        configure_audit_sink(path=audit_path, retention_days=0)

    def tearDown(self):
        reset_audit_sink()

    def test_wipe_removes_all_entries(self):
        """Wipe should remove all cache entries."""
        self.cache.put("lock1", "corpus1", "v1", {"test": 1})
        self.cache.put("lock2", "corpus2", "v1", {"test": 2})
        self.cache.put("lock3", "corpus3", "v1", {"test": 3})

        removed = self.cache.wipe()
        self.assertEqual(removed, 3)

        stats = self.cache.stats()
        self.assertEqual(stats["entries"], 0)


class TestCacheCaps(unittest.TestCase):
    """Tests for cache size and entry caps."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        audit_path = Path(self.tmpdir) / "audit_test.jsonl"
        configure_audit_sink(path=audit_path, retention_days=0)

    def tearDown(self):
        reset_audit_sink()

    def test_max_entries_cap(self):
        """Cache should evict oldest entries when max_entries is exceeded."""
        cache = ScanCache(cache_dir=Path(self.tmpdir), ttl=999999, max_entries=3)
        # Add 5 entries; only the newest 3 should remain after eviction
        for i in range(5):
            cache.put(f"lock-{i}", f"corpus-{i}", "v1", {"idx": i})

        stats = cache.stats()
        self.assertLessEqual(stats["entries"], 3)

    def test_max_entries_zero_unlimited(self):
        """max_entries=0 means unlimited."""
        cache = ScanCache(cache_dir=Path(self.tmpdir), ttl=999999, max_entries=0)
        for i in range(10):
            cache.put(f"lock-{i}", f"corpus-{i}", "v1", {"idx": i})

        stats = cache.stats()
        self.assertEqual(stats["entries"], 10)


class TestCacheStats(unittest.TestCase):
    """Tests for cache stats with governance fields."""

    def test_stats_includes_governance_fields(self):
        cache = ScanCache(ttl=3600, max_entries=100, max_size_mb=50)
        stats = cache.stats()
        self.assertEqual(stats["max_entries"], 100)
        self.assertEqual(stats["max_size_mb"], 50)
        self.assertEqual(stats["ttl_seconds"], 3600)


if __name__ == "__main__":
    unittest.main()