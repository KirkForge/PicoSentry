from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse


class HTTPSEnforcementMiddleware(BaseHTTPMiddleware):

    def __init__(self, app, enabled: bool = False, health_paths: tuple = ("/health", "/healthz")):
        super().__init__(app)
        self.enabled = enabled
        self.health_paths = health_paths

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)


        if request.url.path in self.health_paths:
            return await call_next(request)


        forwarded_proto = request.headers.get("x-forwarded-proto", "")
        if request.url.scheme == "https" or forwarded_proto == "https":
            return await call_next(request)


        https_url = request.url.replace(scheme="https")
        return RedirectResponse(str(https_url), status_code=301)
