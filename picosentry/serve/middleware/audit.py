import json
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger("picoshogun.Audit")


_auth_svc = None


def _get_auth_service():
    global _auth_svc
    if _auth_svc is None:
        try:
            from picosentry.serve.services.auth import AuthService

            _auth_svc = AuthService()
        except ImportError:
            pass
    return _auth_svc


def _get_db():
    try:
        from picosentry.serve.database.manager import db

        return db
    except ImportError:
        return None


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        import time

        start_time = time.time()

        response = await call_next(request)

        duration = time.time() - start_time

        _user_id = None

        auth_svc = _get_auth_service()
        if auth_svc:
            auth_header = request.headers.get("authorization", "")
            api_key = request.headers.get("x-api-key", "")

            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                try:
                    payload = auth_svc.validate_token(token)
                    if payload:
                        _user_id = payload.get("user_id")
                except Exception:
                    pass
            elif api_key:
                try:
                    key_info = auth_svc.validate_api_key(api_key)
                    if key_info:
                        _user_id = key_info.get("user_id")
                except Exception:
                    pass

        if _user_id is None:
            auth_header = request.headers.get("authorization", "")
            _user_id = 0 if auth_header.startswith("Bearer ") else -1  # 0=anon auth, -1=unauthenticated

        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        status_code = response.status_code
        method = request.method
        path = str(request.url.path)
        query = str(request.url.query) if request.url.query else None

        details = {
            "method": method,
            "path": path,
            "query": query,
            "status_code": status_code,
            "duration_ms": round(duration * 1000, 2),
        }

        db = _get_db()
        if db:
            try:
                db.execute_insert(
                    """
                    INSERT INTO audit_log (action, user_id, resource_type, resource_id, details, ip_address, user_agent)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        method,
                        _user_id if _user_id is not None else -1,
                        "api",
                        path,
                        json.dumps(details),
                        ip_address,
                        user_agent,
                    ),
                )
            except Exception:
                logger.exception("Audit DB insert failed")

        logger.info("API %s %s - %s (%.3fs) user=%s", method, path, status_code, duration, _user_id)

        return response
