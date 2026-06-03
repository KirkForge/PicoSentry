"""Security headers middleware — adds security headers to all responses."""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to every HTTP response.

    Headers applied:
    - Strict-Transport-Security (HSTS)
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - X-XSS-Protection: 0 (modern browsers rely on CSP instead)
    - Referrer-Policy: strict-origin-when-cross-origin
    - Permissions-Policy: restrictive defaults
    - Content-Security-Policy: default-src 'self'
    - X-Request-ID: propagated from incoming or generated
    """

    def __init__(self, app, hsts_max_age: int = 31536000, csp: str = None):
        super().__init__(app)
        self.hsts_max_age = hsts_max_age
        self.csp = csp or "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:"

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # HSTS — only meaningful over HTTPS, but set regardless
        response.headers["Strict-Transport-Security"] = f"max-age={self.hsts_max_age}; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = self.csp
        response.headers["X-Request-ID"] = getattr(request.state, "request_id", request.headers.get("X-Request-ID", ""))

        return response
