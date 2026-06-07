from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SecurityHeadersMiddleware(BaseHTTPMiddleware):

    def __init__(self, app, hsts_max_age: int = 31536000, csp: str | None = None):
        super().__init__(app)
        self.hsts_max_age = hsts_max_age
        self.csp = csp or "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:"

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)


        response.headers["Strict-Transport-Security"] = f"max-age={self.hsts_max_age}; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = self.csp
        response.headers["X-Request-ID"] = getattr(request.state, "request_id", request.headers.get("X-Request-ID", ""))

        return response
