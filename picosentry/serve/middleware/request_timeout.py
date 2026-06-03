"""Request timeout middleware — terminates requests that exceed a time limit."""
import asyncio

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class RequestTimeoutMiddleware(BaseHTTPMiddleware):
    """Cancel request processing after a configurable timeout.

    Default: 30 seconds. Returns 504 Gateway Timeout when exceeded.
    """

    def __init__(self, app, timeout_seconds: int = 30):
        super().__init__(app)
        self.timeout_seconds = timeout_seconds

    async def dispatch(self, request: Request, call_next):
        try:
            return await asyncio.wait_for(call_next(request), timeout=self.timeout_seconds)
        except asyncio.TimeoutError:
            return JSONResponse(
                {"error": "Request timed out", "timeout_seconds": self.timeout_seconds},
                status_code=504,
            )
