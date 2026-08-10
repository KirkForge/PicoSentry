import hashlib
import json
import logging
import sqlite3
import threading
from typing import Any, cast

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

try:
    import psycopg2
except ImportError:
    psycopg2 = cast("Any", None)

logger = logging.getLogger("picoshogun.Audit")

_AUDIT_DB_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
    sqlite3.Error,
)
if psycopg2 is not None:
    _AUDIT_DB_ERRORS = (*_AUDIT_DB_ERRORS, psycopg2.Error)


_auth_svc = None
_audit_lock = threading.Lock()


class _AuditChain:
    __slots__ = ("prev_hash",)

    def __init__(self) -> None:
        self.prev_hash: str = ""


_audit_chain = _AuditChain()


def _seed_chain(db) -> None:
    """Resume the hash chain from the last committed row_hash.

    The chain is in-memory only; without this the first row written after a
    process restart would link to prev_hash="" even though the last committed
    row has a non-empty row_hash, breaking tamper-evidence across restarts.
    """
    if _audit_chain.prev_hash:
        return
    try:
        row = db.execute_one("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1")
    except _AUDIT_DB_ERRORS:
        return
    if row and row.get("row_hash"):
        _audit_chain.prev_hash = row["row_hash"]


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
                except (ValueError, KeyError, TypeError, RuntimeError):
                    logger.debug("Token validation failed in audit middleware")
            elif api_key:
                try:
                    key_info = auth_svc.validate_api_key(api_key)
                    if key_info:
                        _user_id = key_info.get("user_id")
                except (ValueError, KeyError, TypeError, RuntimeError):
                    logger.debug("API key validation failed in audit middleware")

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
                details_json = json.dumps(details, sort_keys=True)
                with _audit_lock:
                    _seed_chain(db)
                    parts = [
                        _audit_chain.prev_hash,
                        method,
                        str(_user_id),
                        path,
                        details_json,
                        ip_address or "",
                    ]
                    canonical = "|".join(parts)
                    row_hash = hashlib.sha256(canonical.encode()).hexdigest()
                    db.execute_insert(
                        """
                        INSERT INTO audit_log (action, user_id, resource_type,
                            resource_id, details, ip_address, user_agent,
                            prev_hash, row_hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            method,
                            _user_id if _user_id is not None else -1,
                            "api",
                            path,
                            details_json,
                            ip_address,
                            user_agent,
                            _audit_chain.prev_hash,
                            row_hash,
                        ),
                    )
                    _audit_chain.prev_hash = row_hash
            except _AUDIT_DB_ERRORS:
                logger.exception("Audit DB insert failed")

        logger.info("API %s %s - %s (%.3fs) user=%s", method, path, status_code, duration, _user_id)

        return response
