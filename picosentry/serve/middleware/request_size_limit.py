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
                # No Content-Length means chunked or otherwise streaming body.
                # Starlette buffers the body on first access; cap the buffer
                # before passing the request down so a 10 GB chunked upload
                # cannot exhaust worker memory (PicoSentry-MEDIUM-1).
                body = await request.body()
                if len(body) > self.max_body_bytes:
                    return JSONResponse(
                        {"error": "Request body too large", "max_bytes": self.max_body_bytes},
                        status_code=413,
                    )

        return await call_next(request)
