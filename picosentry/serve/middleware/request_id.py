"""Request ID / correlation ID middleware for distributed tracing."""
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Generate or propagate a request ID for every request.

    - If incoming request has X-Request-ID, propagate it.
    - Otherwise, generate a new UUID4 request ID.
    - Attach the request ID to response headers and request.state.
    """

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
