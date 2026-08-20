from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0


class VerdictCache:
    def __init__(self, ttl_seconds: int = 3600, max_entries: int = 10_000) -> None:
        self._ttl = ttl_seconds
        self._max_entries = max_entries  # ponytail: 10k default; LRU if hot keys get evicted
        self._store: dict[tuple[str, str, str], tuple[float, object]] = {}
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        # ThreadingHTTPServer serves one handler thread per request; get/put/evict
        # mutate shared dicts and counters. A single coarse lock is the smallest
        # fix — verdict cache ops are sub-millisecond and never block on I/O, so
        # contention is negligible vs. the upstream fetch that follows (WO6-017).
        self._lock = threading.Lock()

    def get(self, ecosystem: str, name: str, version: str):
        key = (ecosystem, name, version)
        with self._lock:
            self._evict_expired()
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            expires_at, verdict = entry
            if time.monotonic() > expires_at:
                del self._store[key]
                self._evictions += 1
                self._misses += 1
                return None
            self._hits += 1
            return verdict

    def put(self, ecosystem: str, name: str, version: str, verdict: object) -> None:
        key = (ecosystem, name, version)
        with self._lock:
            self._evict_expired()
            if key not in self._store and len(self._store) >= self._max_entries:
                oldest = min(self._store, key=lambda k: self._store[k][0])
                del self._store[oldest]
                self._evictions += 1
            self._store[key] = (time.monotonic() + self._ttl, verdict)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0

    def stats(self) -> CacheStats:
        with self._lock:
            self._evict_expired()
            return CacheStats(
                hits=self._hits,
                misses=self._misses,
                evictions=self._evictions,
                size=len(self._store),
            )

    def _evict_expired(self) -> None:
        # Caller holds _lock.
        now = time.monotonic()
        expired = [k for k, (exp, _) in self._store.items() if now > exp]
        for k in expired:
            del self._store[k]
            self._evictions += 1
