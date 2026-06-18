import logging
import threading
import time
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger("picoshogun.RateLimit")


class RateLimitMiddleware(BaseHTTPMiddleware):

    def __init__(
        self,
        app,
        max_requests_per_ip: int = 100,
        max_requests_per_org: int = 1000,
        window: int = 60,
        max_buckets: int = 100000,
        persist: bool = False,
    ):
        super().__init__(app)
        self.max_requests_per_ip = max_requests_per_ip
        self.max_requests_per_org = max_requests_per_org
        self.window = window
        self.max_buckets = max_buckets
        self.persist = persist

        self.ip_requests: dict[str, list] = defaultdict(list)
        self.org_requests: dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()
        self._last_eviction = time.time()
        self._last_flush = time.time()

        if self.persist:
            self._init_db()
            self._restore_from_db()


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
            restored_ip, restored_org,
        )

    def _flush_to_db(self):
        if not self.persist:
            return

        db = self._get_db()
        now = time.time()

        with self._lock:
            try:

                db.execute("DELETE FROM rate_limit_counters")


                for key, timestamps in self.ip_requests.items():
                    if timestamps and timestamps[-1] > now - self.window:
                        db.execute_insert(
                            "INSERT INTO rate_limit_counters (bucket_type, bucket_key, timestamps) VALUES (?, ?, ?)",
                            ("ip", key, ",".join(str(t) for t in timestamps)),
                        )


                for key, timestamps in self.org_requests.items():
                    if timestamps and timestamps[-1] > now - self.window:
                        db.execute_insert(
                            "INSERT INTO rate_limit_counters (bucket_type, bucket_key, timestamps) VALUES (?, ?, ?)",
                            ("org", key, ",".join(str(t) for t in timestamps)),
                        )
            except Exception as exc:
                logger.warning("Rate limit persistence flush failed: %s", exc)


    def _evict_if_needed(self, now: float):
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
            for k in sorted_keys[:len(self.ip_requests) - self.max_buckets]:
                del self.ip_requests[k]
        if len(self.org_requests) > self.max_buckets:
            sorted_keys = sorted(
                self.org_requests,
                key=lambda k: self.org_requests[k][-1] if self.org_requests[k] else 0,
            )
            for k in sorted_keys[:len(self.org_requests) - self.max_buckets]:
                del self.org_requests[k]


        if self.persist and now - self._last_flush > 60:
            self._last_flush = now
            self._flush_to_db()

    def _clean_and_count(self, buckets: dict, key: str, now: float) -> int:
        buckets[key] = [t for t in buckets[key] if now - t < self.window]
        return len(buckets[key])

    async def dispatch(self, request: Request, call_next):
        now = time.time()
        client_ip = request.client.host if request.client else "unknown"

        with self._lock:
            self._evict_if_needed(now)


            org_api_key = request.headers.get("X-Org-API-Key", "")
            rate_limited = False
            if org_api_key and isinstance(org_api_key, str) and (org_api_key.startswith(("sk_", "pk_"))):
                org_count = self._clean_and_count(self.org_requests, org_api_key, now)
                if org_count >= self.max_requests_per_org:
                    retry_after = int(self.window - (now - self.org_requests[org_api_key][0]) + 1)
                    rate_limited = True
                    rate_limit_response = JSONResponse(
                        {
                            "error": "Organization rate limit exceeded",
                            "limit": self.max_requests_per_org,
                            "window": f"{self.window}s",
                        },
                        status_code=429,
                        headers={"Retry-After": str(max(retry_after, 1))},
                    )
                else:
                    self.org_requests[org_api_key].append(now)


            if not rate_limited:
                ip_count = self._clean_and_count(self.ip_requests, client_ip, now)
                if ip_count >= self.max_requests_per_ip:
                    retry_after = int(self.window - (now - self.ip_requests[client_ip][0]) + 1)
                    rate_limited = True
                    rate_limit_response = JSONResponse(
                        {
                            "error": "Rate limit exceeded",
                            "limit": self.max_requests_per_ip,
                            "window": f"{self.window}s",
                        },
                        status_code=429,
                        headers={"Retry-After": str(max(retry_after, 1))},
                    )
                else:
                    self.ip_requests[client_ip].append(now)

        if rate_limited:
            return rate_limit_response
        return await call_next(request)
