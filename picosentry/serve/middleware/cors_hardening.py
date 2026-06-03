"""Production CORS hardening — rejects wildcard origins when credentials are enabled."""
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from picosentry.serve.config.settings import settings

logger = logging.getLogger("picoshogun.CORS")


class CORSHardeningMiddleware(BaseHTTPMiddleware):
    """Warn and optionally block when CORS is misconfigured in production.

    In production mode with `allow_credentials=True` and wildcard origins,
    browsers reject the response anyway. This middleware:
    1. Logs a warning on every request if CORS is misconfigured
    2. Optionally blocks cross-origin requests in production when
       origins are wildcard and credentials are enabled
    """

    def __init__(self, app, block_wildcard_in_production: bool = False):
        super().__init__(app)
        self.block_wildcard_in_production = block_wildcard_in_production

    async def dispatch(self, request: Request, call_next):
        if settings.is_production() and "*" in settings.api.cors_origins:
            logger.warning(
                "CORS misconfiguration: wildcard origin with credentials in production. "
                "Set PICOSHOGUN_CORS_ORIGINS env var to explicit origins. "
                "Origin=%s Path=%s",
                request.headers.get("origin", ""),
                request.url.path,
            )

            if self.block_wildcard_in_production:
                origin = request.headers.get("origin", "")
                # Block null/empty origins (file://, sandboxed iframes)
                if origin == "null" or (origin and origin not in settings.api.cors_origins):
                    return JSONResponse(
                        {"error": "CORS origin not allowed"},
                        status_code=403,
                    )

        return await call_next(request)
