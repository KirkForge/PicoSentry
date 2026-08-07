from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0


class VerdictCache:
    def __init__(self, ttl_seconds: int = 3600) -> None:
        self._ttl = ttl_seconds
        self._store: dict[tuple[str, str, str], tuple[float, object]] = {}
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def get(self, ecosystem: str, name: str, version: str):
        self._evict_expired()
        key = (ecosystem, name, version)
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
        self._evict_expired()
        key = (ecosystem, name, version)
        self._store[key] = (time.monotonic() + self._ttl, verdict)

    def clear(self) -> None:
        self._store.clear()
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def stats(self) -> CacheStats:
        self._evict_expired()
        return CacheStats(
            hits=self._hits,
            misses=self._misses,
            evictions=self._evictions,
            size=len(self._store),
        )

    def _evict_expired(self) -> None:
        now = time.monotonic()
        expired = [k for k, (exp, _) in self._store.items() if now > exp]
        for k in expired:
            del self._store[k]
            self._evictions += 1
