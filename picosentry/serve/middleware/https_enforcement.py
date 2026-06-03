"""HTTPS enforcement middleware — redirects HTTP to HTTPS in production."""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse


class HTTPSEnforcementMiddleware(BaseHTTPMiddleware):
    """Redirect HTTP requests to HTTPS when running in production.

    Skips redirect for:
    - Health check endpoints (allow HTTP for load balancers)
    - Requests already using HTTPS
    """

    def __init__(self, app, enabled: bool = False, health_paths: tuple = ("/health", "/healthz")):
        super().__init__(app)
        self.enabled = enabled
        self.health_paths = health_paths

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)

        # Allow health checks over HTTP for load balancer probes
        if request.url.path in self.health_paths:
            return await call_next(request)

        # Check if request is already HTTPS (or running behind a proxy that sets X-Forwarded-Proto)
        forwarded_proto = request.headers.get("x-forwarded-proto", "")
        if request.url.scheme == "https" or forwarded_proto == "https":
            return await call_next(request)

        # Redirect to HTTPS
        https_url = request.url.replace(scheme="https")
        return RedirectResponse(str(https_url), status_code=301)
