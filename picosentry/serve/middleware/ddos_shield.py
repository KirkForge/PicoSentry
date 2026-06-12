import logging
from typing import ClassVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger("picoshogun.DDoSShield")


class DDoSShieldMiddleware(BaseHTTPMiddleware):


    HIGH_RISK_PATHS: ClassVar[set[str]] = {"/api/v1/scan", "/api/v1/auth/token", "/api/v1/projects"}

    # Health and readiness probes are called by load balancers and
    # Kubernetes liveness/readiness checks on a tight schedule (often
    # every 1–5 s).  If the shield 429s them, the LB will mark the pod
    # unhealthy and rotate it out — which makes the shield cause the
    # very outage it's trying to prevent.  These paths bypass the
    # global and per-path buckets entirely.
    HEALTH_PATHS: ClassVar[tuple[str, ...]] = (
        "/health",
        "/healthz",
        "/health/live",
        "/health/ready",
    )

    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled
        self._path_buckets: dict[str, list[float]] = {}
        self._global_bucket: list[float] = []
        self._burst_limit = 50  # requests per 10-second window per path
        self._global_limit = 200  # total requests per 10-second window

    @classmethod
    def _is_health_path(cls, path: str) -> bool:
        """A path is a health probe if it equals one of ``HEALTH_PATHS``
        or is a strict subpath (``/health/live``, ``/health/ready``).
        We do not match ``/health-history`` or other lookalikes — the
        verdict's concern is the load-balancer probes, not arbitrary
        health-flavoured URLs."""
        for prefix in cls.HEALTH_PATHS:
            if path == prefix or path.startswith(prefix + "/"):
                return True
        return False

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)

        # Health probes never count against the global bucket.  They
        # are not user-driven traffic; treating them as such is what
        # produced the integration-test 429s and the load-balancer
        # outage risk.
        if self._is_health_path(request.url.path):
            return await call_next(request)

        import time
        now = time.monotonic()
        cutoff = now - 10.0  # 10-second window


        self._global_bucket = [t for t in self._global_bucket if t > cutoff]


        if len(self._global_bucket) >= self._global_limit:
            logger.warning("DDoS shield: global rate limit exceeded from %s", request.client.host if request.client else "unknown")
            from starlette.responses import JSONResponse
            return JSONResponse({"error": "rate_limit_exceeded", "detail": "Global rate limit exceeded"}, status_code=429)


        path = request.url.path
        if path in self.HIGH_RISK_PATHS:
            bucket = self._path_buckets.get(path, [])
            bucket = [t for t in bucket if t > cutoff]
            if len(bucket) >= self._burst_limit:
                logger.warning("DDoS shield: path burst limit exceeded for %s from %s", path, request.client.host if request.client else "unknown")
                from starlette.responses import JSONResponse
                return JSONResponse({"error": "rate_limit_exceeded", "detail": f"Burst limit exceeded for {path}"}, status_code=429)
            bucket.append(now)
            self._path_buckets[path] = bucket

        self._global_bucket.append(now)
        return await call_next(request)
