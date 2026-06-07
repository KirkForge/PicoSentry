import logging
from typing import ClassVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger("picoshogun.DDoSShield")


class DDoSShieldMiddleware(BaseHTTPMiddleware):


    HIGH_RISK_PATHS: ClassVar[set[str]] = {"/api/v1/scan", "/api/v1/auth/token", "/api/v1/projects"}

    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled
        self._path_buckets: dict[str, list[float]] = {}
        self._global_bucket: list[float] = []
        self._burst_limit = 50  # requests per 10-second window per path
        self._global_limit = 200  # total requests per 10-second window

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
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
