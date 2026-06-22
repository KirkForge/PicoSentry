from typing import ClassVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class DocsRestrictionMiddleware(BaseHTTPMiddleware):
    DOCS_PATHS: ClassVar[set[str]] = {"/docs", "/docs/", "/redoc", "/redoc/"}

    def __init__(self, app, enabled: bool = False):
        super().__init__(app)
        self.enabled = enabled

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)

        if request.url.path in self.DOCS_PATHS:
            return JSONResponse(
                {"error": "API documentation is disabled in production", "path": request.url.path},
                status_code=404,
            )

        return await call_next(request)
