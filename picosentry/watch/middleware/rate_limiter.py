
from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class RateLimitEntry:

    timestamps: list[float] = field(default_factory=list)


class RateLimiter:

    def __init__(self, max_requests: int = 100, window_seconds: int = 60, max_clients: int = 100_000) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_clients = max_clients
        self._clients: dict[str, RateLimitEntry] = defaultdict(RateLimitEntry)
        self._lock = threading.Lock()
        self._last_eviction = time.monotonic()

    def is_allowed(self, client_ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            entry = self._clients[client_ip]
            cutoff = now - self.window_seconds


            entry.timestamps = [ts for ts in entry.timestamps if ts > cutoff]


            if now - self._last_eviction > self.window_seconds:
                self._evict_stale(now)
                self._last_eviction = now

            if len(entry.timestamps) >= self.max_requests:
                return False

            entry.timestamps.append(now)
            return True

    def _evict_stale(self, now: float) -> None:
        cutoff = now - self.window_seconds * 2  # Grace period beyond window
        stale = [ip for ip, entry in self._clients.items() if not entry.timestamps or entry.timestamps[-1] < cutoff]
        for ip in stale:
            del self._clients[ip]

    def reset(self, client_ip: str | None = None) -> None:
        with self._lock:
            if client_ip:
                self._clients.pop(client_ip, None)
            else:
                self._clients.clear()

    @property
    def active_clients(self) -> int:
        with self._lock:
            return len(self._clients)
