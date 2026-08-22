"""WO7-031 — OSV disk-cache _write_cache was O(N²) — _enforce_caps glob+stat on every write.

_write_cache called _enforce_caps unconditionally, which globs + stats the
entire cache dir on each write. Cost grows O(N²) — measured 3x slowdown
between 500 and 1000 entries. The fix gates _enforce_caps with a write
counter (every 50 writes), so the amortized cost is O(N).
"""

from __future__ import annotations

import time
from pathlib import Path

from picosentry.scan.intelligence import OSVClient


class TestWriteCacheBatchedEnforce:
    def test_enforce_caps_not_called_every_write(self, tmp_path: Path, monkeypatch):
        client = OSVClient(cache_dir=tmp_path)
        calls = []
        monkeypatch.setattr(client, "_enforce_caps", lambda: calls.append(1))
        for i in range(10):
            client._write_cache(client._cache_key("npm", f"pkg-{i}"), [{"id": f"t{i}"}])
        assert len(calls) == 0, "first 10 writes must not trigger _enforce_caps (gated every 50)"

    def test_enforce_caps_called_at_threshold(self, tmp_path: Path, monkeypatch):
        client = OSVClient(cache_dir=tmp_path)
        calls = []
        monkeypatch.setattr(client, "_enforce_caps", lambda: calls.append(1))
        for i in range(50):
            client._write_cache(client._cache_key("npm", f"pkg-{i}"), [{"id": f"t{i}"}])
        assert len(calls) == 1, "write #50 triggers _enforce_caps once"

    def test_enforce_caps_called_every_50_writes(self, tmp_path: Path, monkeypatch):
        client = OSVClient(cache_dir=tmp_path)
        calls = []
        monkeypatch.setattr(client, "_enforce_caps", lambda: calls.append(1))
        for i in range(150):
            client._write_cache(client._cache_key("npm", f"pkg-{i}"), [{"id": f"t{i}"}])
        assert len(calls) == 3, "150 writes trigger _enforce_caps exactly 3 times"


class TestWriteCachePerf:
    def test_500_writes_under_3s(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("PICOSENTRY_OSV_MAX_ENTRIES", "0")
        monkeypatch.setenv("PICOSENTRY_OSV_MAX_AGE_SECONDS", "0")
        client = OSVClient(cache_dir=tmp_path)
        start = time.time()
        for i in range(500):
            client._write_cache(client._cache_key("npm", f"pkg-{i}"), [{"id": f"t{i}"}])
        elapsed = time.time() - start
        assert elapsed < 3.0, f"500 writes took {elapsed:.2f}s, expected <3s (was 9.24s pre-fix)"
        assert len(list(tmp_path.glob("*.json"))) == 500

    def test_500_writes_with_existing_entries_under_3s(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("PICOSENTRY_OSV_MAX_ENTRIES", "0")
        monkeypatch.setenv("PICOSENTRY_OSV_MAX_AGE_SECONDS", "0")
        client = OSVClient(cache_dir=tmp_path)
        for i in range(500):
            client._write_cache(client._cache_key("npm", f"seed-{i}"), [{"id": f"s{i}"}])
        start = time.time()
        for i in range(500):
            client._write_cache(client._cache_key("npm", f"pkg-{i}"), [{"id": f"t{i}"}])
        elapsed = time.time() - start
        assert elapsed < 3.0, f"500 writes with 500 existing took {elapsed:.2f}s, expected <3s (was 27.33s pre-fix)"
