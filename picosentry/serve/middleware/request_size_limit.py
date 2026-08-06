from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_body_bytes: int = 10 * 1024 * 1024):
        super().__init__(app)
        self.max_body_bytes = max_body_bytes

    async def dispatch(self, request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH"):
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > self.max_body_bytes:
                        return JSONResponse(
                            {"error": "Request body too large", "max_bytes": self.max_body_bytes},
                            status_code=413,
                        )
                except (ValueError, TypeError):
                    pass
            else:
                # No Content-Length means chunked or streaming body.
                # Read in chunks and stop as soon as we exceed the limit,
                # rather than buffering the entire body into memory first
                # (ponytail: streaming size check prevents OOM from chunked uploads).
                total = 0
                chunks: list[bytes] = []
                async for chunk in request.stream():
                    total += len(chunk)
                    if total > self.max_body_bytes:
                        return JSONResponse(
                            {"error": "Request body too large", "max_bytes": self.max_body_bytes},
                            status_code=413,
                        )
                    chunks.append(chunk)
                # Replace the body with the buffered chunks so downstream
                # handlers can still access request.body().
                # ponytail: _body is Starlette's documented internal for
                # pre-read body; no public API exists for this.
                request._body = b"".join(chunks)

        return await call_next(request)
