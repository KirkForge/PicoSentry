import asyncio
import contextlib
import hashlib
import logging
import sqlite3
import threading
import time
from collections import defaultdict
from typing import Any, cast

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from picosentry.serve.middleware.rate_limit_redis import DENY

logger = logging.getLogger("picoshogun.RateLimit")

try:
    import psycopg2 as _psycopg2
except ImportError:
    _psycopg2 = cast("Any", None)

# Operational DB failures the persistence paths tolerate: sqlite3.OperationalError
# (busy_timeout=15s product expiry under a write-lock holder) is a subclass of
# NEITHER OSError NOR ValueError — catching only those turned DB contention into
# a 500 on every request. psycopg2.Error covers the postgres backend.
# RuntimeError is included to mirror scheduler._DB_SOFT_ERRORS — a generic
# backend blip surfacing as RuntimeError must degrade to memory-only, not 500.
_DB_SOFT_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    RuntimeError,
    ValueError,
    sqlite3.Error,
) + ((_psycopg2.Error,) if _psycopg2 is not None else ())

# ponytail: ceiling on flush batch length. max_buckets=100000 with a SELECT+upsert
# per bucket under a BEGIN IMMEDIATE holder serialized every request on a 15s
# busy_timeout expiry. Cap the per-tick flush so a background sweep is bounded;
# the next tick resumes. Upgrade path: per-bucket delta persistence if the cap
# ever throttles cross-worker convergence.
_FLUSH_BATCH = 1000


def _get_client_ip(request: Request, trusted_proxies: list[str] | None = None) -> str:
    if trusted_proxies:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            ips = [ip.strip() for ip in forwarded.split(",")]
            for ip in reversed(ips):
                if ip not in trusted_proxies:
                    return ip
    return request.client.host if request.client else "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        max_requests_per_ip: int = 100,
        max_requests_per_org: int = 1000,
        window: int = 60,
        max_buckets: int = 100000,
        persist: bool = False,
        backend: str = "memory",
        backend_url: str = "redis://localhost:6379/0",
        backend_instance: Any | None = None,
        redis_fail_closed: bool = False,
        exempt_paths: set[str] | None = None,
        trusted_proxies: list[str] | None = None,
        sync_interval: float = 60.0,
    ):
        super().__init__(app)
        self.max_requests_per_ip = max_requests_per_ip
        self.max_requests_per_org = max_requests_per_org
        self.window = window
        self.max_buckets = max_buckets
        self.persist = persist
        self.backend_name = backend.lower()
        self.backend_url = backend_url
        self.redis_fail_closed = redis_fail_closed
        self.exempt_paths = exempt_paths or set()
        self.trusted_proxies = trusted_proxies or []
        # How often counters flush to / re-sync from the shared table. The
        # 60s default matches the historical single-instance persistence
        # cadence; multi-worker deployments pass a few seconds instead
        # (server.py wiring) — the residual cross-worker undercount window
        # is this interval, a documented ceiling of the sqlite backend.
        self.sync_interval = sync_interval

        self.ip_requests: dict[str, list] = defaultdict(list)
        self.org_requests: dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()
        self._last_eviction = time.time()
        self._last_flush = time.time()
        self._redis_backend: Any | None = None

        if backend_instance is not None:
            self._redis_backend = backend_instance
        elif self.backend_name == "redis":
            from picosentry.serve.middleware.rate_limit_redis import RedisRateLimitBackend

            self._redis_backend = RedisRateLimitBackend(
                redis_url=self.backend_url,
                window=self.window,
                fail_closed=self.redis_fail_closed,
            )
            logger.info("Rate limit Redis backend configured: %s", self.backend_url)

        if self.persist:
            self._init_db()
            self._restore_from_db()
            self._start_flush_thread()

    def _start_flush_thread(self) -> None:
        # Background cadence thread: flush+sync runs OFF the request path so
        # DB contention (15s busy_timeout) can never stall a request. The
        # thread snapshots buckets under the lock, then transacts outside.
        self._flush_stop = threading.Event()
        self._flush_thread = threading.Thread(target=self._flush_loop, name=f"ratelimit-flush-{id(self)}", daemon=True)
        self._flush_thread.start()

    def _flush_loop(self) -> None:
        while not self._flush_stop.wait(self.sync_interval):
            try:
                self._background_flush()
            except _DB_SOFT_ERRORS:
                logger.warning("Rate limit background flush tick failed", exc_info=True)
            except Exception:
                logger.exception("Rate limit background flush tick crashed")

    def _background_flush(self) -> None:
        now = time.time()
        # Snapshot under the lock, transact outside — never hold _lock across
        # a DB transaction that may block 15s on a busy_timeout expiry.
        with self._lock:
            self._evict_if_needed(now)
            ip_snap = {k: list(v) for k, v in self.ip_requests.items() if v and v[-1] > now - self.window}
            org_snap = {k: list(v) for k, v in self.org_requests.items() if v and v[-1] > now - self.window}
        self._flush_snapshot(ip_snap, org_snap, now)
        try:
            self._sync_from_db(now)
        except _DB_SOFT_ERRORS:
            logger.warning("Rate limit persistence sync failed", exc_info=True)

    def shutdown(self) -> None:
        """Stop the background flush thread (tests, graceful shutdown)."""
        stop = getattr(self, "_flush_stop", None)
        if stop is not None:
            stop.set()
        t = getattr(self, "_flush_thread", None)
        if t is not None and t.is_alive():
            t.join(timeout=2)

    def _get_db(self):
        from picosentry.serve.database.manager import db

        return db

    def _init_db(self):
        db = self._get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS rate_limit_counters (
                bucket_type TEXT NOT NULL,
                bucket_key TEXT NOT NULL,
                timestamps TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (bucket_type, bucket_key)
            )
        """)
        logger.info("Rate limit persistence table initialized")

    def _restore_from_db(self):
        db = self._get_db()
        now = time.time()
        cutoff = now - self.window
        restored_ip = 0
        restored_org = 0

        rows = db.execute("SELECT bucket_type, bucket_key, timestamps FROM rate_limit_counters")
        for row in rows:
            bucket_type = row["bucket_type"]
            bucket_key = row["bucket_key"]
            try:
                timestamps = [float(t) for t in row["timestamps"].split(",") if t]
            except (ValueError, TypeError):
                continue

            valid = [t for t in timestamps if t > cutoff]
            if valid:
                if bucket_type == "ip":
                    self.ip_requests[bucket_key] = valid
                    restored_ip += 1
                elif bucket_type == "org":
                    self.org_requests[bucket_key] = valid
                    restored_org += 1

        logger.info(
            "Rate limit persistence restored: %d IP buckets, %d org buckets",
            restored_ip,
            restored_org,
        )

    def _flush_snapshot(self, ip_snap: dict, org_snap: dict, now: float) -> None:
        """Flush pre-snapshotted buckets to the shared table OUTSIDE _lock.

        The caller (_background_flush) snapshots under the lock; this runs the
        BEGIN IMMEDIATE transaction without holding the request-path lock, so
        a busy_timeout expiry degrades to memory-only instead of stalling
        every request for 15s.
        """
        if not self.persist:
            return

        db = self._get_db()
        cutoff = now - self.window
        flushed = 0
        # MERGE-upsert, not DELETE+re-INSERT: with more than one worker
        # persisting to the same table, a replace-all clobbered the other
        # workers' counters (last writer wins). Each request is recorded by
        # exactly one worker, so the union of timestamp sets is the true
        # global set — idempotent under any interleaving.
        try:
            with db.transaction(immediate=True) as conn:
                for bucket_type, buckets in (("ip", ip_snap), ("org", org_snap)):
                    for key, timestamps in buckets.items():
                        if not (timestamps and timestamps[-1] > cutoff):
                            continue
                        row = db.execute_on(
                            conn,
                            "SELECT timestamps FROM rate_limit_counters WHERE bucket_type = ? AND bucket_key = ?",
                            (bucket_type, key),
                        )
                        merged = set(timestamps)
                        if row:
                            with contextlib.suppress(ValueError, TypeError):
                                foreign = [float(x) for x in row[0]["timestamps"].split(",") if x]
                                merged.update(t for t in foreign if t > cutoff)
                        merged_ts = ",".join(str(t) for t in sorted(merged))
                        if db.backend == "postgres":
                            db.execute_on(
                                conn,
                                "INSERT INTO rate_limit_counters (bucket_type, bucket_key, timestamps) "
                                "VALUES (?, ?, ?) ON CONFLICT (bucket_type, bucket_key) "
                                "DO UPDATE SET timestamps = EXCLUDED.timestamps, updated_at = CURRENT_TIMESTAMP",
                                (bucket_type, key, merged_ts),
                            )
                        else:
                            db.execute_on(
                                conn,
                                "INSERT OR REPLACE INTO rate_limit_counters "
                                "(bucket_type, bucket_key, timestamps, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                                (bucket_type, key, merged_ts),
                            )
                        flushed += 1
                        if flushed >= _FLUSH_BATCH:
                            return
        except _DB_SOFT_ERRORS:
            logger.warning("Rate limit persistence flush failed; degrading to memory-only", exc_info=True)

    def _flush_to_db(self) -> None:
        """Synchronous flush: snapshot under lock, transact outside.

        Compatibility entrypoint for tests and shutdown. The request path
        uses _background_flush (off the request path); this snapshots the
        live dicts and delegates to _flush_snapshot.
        """
        if not self.persist:
            return
        now = time.time()
        with self._lock:
            ip_snap = {k: list(v) for k, v in self.ip_requests.items() if v and v[-1] > now - self.window}
            org_snap = {k: list(v) for k, v in self.org_requests.items() if v and v[-1] > now - self.window}
        self._flush_snapshot(ip_snap, org_snap, now)

    def _sync_from_db(self, now: float):
        """Merge the shared table's counters into the local dicts.

        The multi-worker half of the persistence protocol: flush pushes our
        observations out, this pulls the other workers' in. Same union
        semantics — a bucket key we have never seen locally (all our
        traffic came via the other worker) is adopted from the row.

        Called from the background _flush_loop; takes _lock to mutate the
        request-path dicts safely.
        """
        if not self.persist:
            return

        db = self._get_db()
        cutoff = now - self.window
        rows = db.execute("SELECT bucket_type, bucket_key, timestamps FROM rate_limit_counters")
        with self._lock:
            for row in rows:
                try:
                    foreign = [t for t in (float(x) for x in row["timestamps"].split(",") if x) if t > cutoff]
                except (ValueError, TypeError):
                    continue
                if not foreign:
                    continue
                buckets = self.ip_requests if row["bucket_type"] == "ip" else self.org_requests
                merged = sorted({*buckets.get(row["bucket_key"], []), *foreign})
                buckets[row["bucket_key"]] = merged

    def _evict_if_needed(self, now: float):
        # Eviction only — flush/sync moved to the background _flush_loop so
        # DB contention can never stall the request path. Caller holds _lock.
        if now - self._last_eviction < 60:
            return
        self._last_eviction = now

        cutoff = now - self.window
        stale_ips = [k for k, v in self.ip_requests.items() if not v or v[-1] < cutoff]
        stale_orgs = [k for k, v in self.org_requests.items() if not v or v[-1] < cutoff]

        for k in stale_ips:
            del self.ip_requests[k]
        for k in stale_orgs:
            del self.org_requests[k]

        if len(self.ip_requests) > self.max_buckets:
            sorted_keys = sorted(self.ip_requests, key=lambda k: self.ip_requests[k][-1] if self.ip_requests[k] else 0)
            for k in sorted_keys[: len(self.ip_requests) - self.max_buckets]:
                del self.ip_requests[k]
        if len(self.org_requests) > self.max_buckets:
            sorted_keys = sorted(
                self.org_requests,
                key=lambda k: self.org_requests[k][-1] if self.org_requests[k] else 0,
            )
            for k in sorted_keys[: len(self.org_requests) - self.max_buckets]:
                del self.org_requests[k]

    def _clean_and_count(self, buckets: dict, key: str, now: float) -> int:
        buckets[key] = [t for t in buckets[key] if now - t < self.window]
        return len(buckets[key])

    def _record_and_check(
        self,
        bucket_type: str,
        bucket_key: str,
        max_requests: int,
        now: float,
        buckets: dict,
    ) -> tuple[bool, int]:
        """Record a request and return (rate_limited, retry_after_seconds).

        Uses the Redis backend when configured; otherwise the in-memory dict.
        The Redis roundtrip deliberately runs OUTSIDE the global lock — Redis
        is concurrency-safe server-side, and holding the lock across the
        network call would serialize all requests on Redis latency.
        """
        if self._redis_backend is not None:
            count = self._redis_backend.record_and_count(bucket_type, bucket_key)
            if count == DENY:
                # Redis down and fail-closed: reject rather than degrade to
                # per-replica limits.
                return True, self.window
            if count >= 0:
                if count > max_requests:
                    # Already recorded; estimate worst-case retry time.
                    return True, self.window
                return False, 0
            # Redis failed (fail-open): fall through to in-memory for this request.

        with self._lock:
            self._evict_if_needed(now)
            count = self._clean_and_count(buckets, bucket_key, now) + 1
            buckets[bucket_key].append(now)
            if count > max_requests:
                oldest = buckets[bucket_key][0] if buckets[bucket_key] else now - self.window
                retry_after = int(self.window - (now - oldest) + 1)
                return True, max(retry_after, 1)
            return False, 0

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self.exempt_paths:
            return await call_next(request)

        now = time.time()
        client_ip = _get_client_ip(request, self.trusted_proxies)

        # No global lock here: Redis-backed checks are lock-free and the
        # in-memory path takes the lock only for dict mutation.
        # The check runs in the threadpool: the sync redis-py roundtrip
        # (1s connect/socket timeouts, up to 2 calls per request) must never
        # stall the event loop — a configured-but-down Redis otherwise adds
        # ~2s of loop stall to every request, unauthenticated ones included.
        org_api_key = request.headers.get("X-Org-API-Key", "")
        if org_api_key and isinstance(org_api_key, str) and (org_api_key.startswith(("sk_", "pk_"))):
            rate_limited, retry_after = await asyncio.to_thread(
                self._record_and_check,
                "org",
                hashlib.sha256(org_api_key.encode()).hexdigest(),
                self.max_requests_per_org,
                now,
                self.org_requests,
            )
            if rate_limited:
                return JSONResponse(
                    {
                        "error": "Organization rate limit exceeded",
                        "limit": self.max_requests_per_org,
                        "window": f"{self.window}s",
                    },
                    status_code=429,
                    headers={"Retry-After": str(retry_after)},
                )

        rate_limited, retry_after = await asyncio.to_thread(
            self._record_and_check,
            "ip",
            client_ip,
            self.max_requests_per_ip,
            now,
            self.ip_requests,
        )
        if rate_limited:
            return JSONResponse(
                {
                    "error": "Rate limit exceeded",
                    "limit": self.max_requests_per_ip,
                    "window": f"{self.window}s",
                },
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)
