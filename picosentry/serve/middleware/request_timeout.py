import asyncio
import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger("picoshogun.RequestTimeout")


class RequestTimeoutMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        timeout_seconds: float = 30,
        long_running_paths: tuple[str, ...] = (),
        long_timeout_seconds: float = 3660,
    ):
        super().__init__(app)
        self.timeout_seconds = timeout_seconds
        self.long_running_paths = long_running_paths
        self.long_timeout_seconds = long_timeout_seconds

    def _timeout_for(self, path: str) -> float:
        if any(path.startswith(prefix) or path.endswith(prefix) for prefix in self.long_running_paths):
            return self.long_timeout_seconds
        return self.timeout_seconds

    async def dispatch(self, request: Request, call_next):
        timeout = self._timeout_for(request.url.path)
        started = time.monotonic()
        try:
            return await asyncio.wait_for(call_next(request), timeout=timeout)
        except asyncio.TimeoutError:
            duration = time.monotonic() - started
            logger.warning("Request timed out: %s %s after %.1fs", request.method, request.url.path, duration)
            request_id = getattr(request.state, "request_id", None)
            headers = {"X-Request-ID": request_id} if request_id else None
            return JSONResponse(
                {"error": "Request timed out", "timeout_seconds": timeout},
                status_code=504,
                headers=headers,
            )
