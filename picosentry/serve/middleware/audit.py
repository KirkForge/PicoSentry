import asyncio
import atexit
import logging
import queue
import threading
import time
from typing import Any, cast

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from picosentry.serve.middleware.request_id import _request_id_var

try:
    import psycopg2
except ImportError:
    psycopg2 = cast("Any", None)

logger = logging.getLogger("picoshogun.Audit")

_AUDIT_QUEUE_SIZE = 1024
# How long a request may wait for its audit row to reach the DB. The write
# itself always runs on the writer thread — the event loop is never blocked;
# this only bounds response latency when the writer is backed up.
# ponytail: waiting keeps rows durable before the response and append failures
# logged synchronously with the request; drop to 0 (pure fire-and-forget) once
# audit failure handling is decoupled from request completion.
_AUDIT_WRITE_WAIT_SECONDS = 1.0


class _AuditItem:
    __slots__ = ("done", "fields")

    def __init__(self, fields: dict):
        self.fields = fields
        self.done = threading.Event()


class _AuditWriter:
    """Single daemon writer thread for audit rows.

    append_audit_row() opens a BEGIN IMMEDIATE transaction and fsyncs; calling
    it inline in dispatch blocked the event loop on every request. One FIFO
    queue + one writer thread also preserves the hash chain's global append
    order.
    """

    def __init__(self, maxsize: int = _AUDIT_QUEUE_SIZE):
        self._queue: queue.Queue[_AuditItem] = queue.Queue(maxsize=maxsize)
        self.dropped = 0  # monotonic drop counter; metric wiring later
        self._thread = threading.Thread(target=self._run, name="audit-writer", daemon=True)
        self._thread.start()
        # Best-effort drain at shutdown. ponytail: BaseHTTPMiddleware has no
        # lifespan hook we can reach without editing server.py; atexit runs
        # before daemon threads are killed, so queued rows get one flush.
        atexit.register(self.flush)

    def submit(self, fields: dict) -> threading.Event | None:
        """Enqueue one append_audit_row() call; returns None when dropped."""
        item = _AuditItem(fields)
        try:
            self._queue.put(item, block=False)
        except queue.Full:
            self.dropped += 1
            from picosentry.serve.services.metrics import metrics

            metrics.set_global_gauge("dropped_audit_records", self.dropped)
            logger.warning("Audit queue full — dropping row (dropped so far: %d)", self.dropped)
            return None
        return item.done

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                # Imported per item so tests (and reloads) can patch the chain.
                from picosentry.serve.services.audit_chain import append_audit_row

                append_audit_row(**item.fields)
            except Exception:
                logger.exception("Unexpected error writing audit row")
            finally:
                item.done.set()

    def flush(self, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while not self._queue.empty() and time.monotonic() < deadline:
            time.sleep(0.01)


_writer: _AuditWriter | None = None
_writer_lock = threading.Lock()


def _get_writer() -> _AuditWriter:
    global _writer
    if _writer is None:
        with _writer_lock:
            if _writer is None:
                _writer = _AuditWriter()
    return _writer


def writer_dropped_count() -> int:
    """Audit rows dropped by a full writer queue (0 before the writer exists)."""
    w = _writer
    return w.dropped if w is not None else 0


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
        _org_id = None

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
                        _org_id = payload.get("org_id")
                except (ValueError, KeyError, TypeError, RuntimeError):
                    logger.debug("Token validation failed in audit middleware")
            elif api_key:
                try:
                    key_info = auth_svc.validate_api_key(api_key)
                    if key_info:
                        _user_id = key_info.get("user_id")
                        _org_id = key_info.get("org_id")
                except (ValueError, KeyError, TypeError, RuntimeError):
                    logger.debug("API key validation failed in audit middleware")

        if _org_id is None:
            org_key = request.headers.get("x-org-api-key", "")
            if org_key.startswith("sk_"):
                try:
                    from picosentry.serve.services.orgs import Organization

                    org = Organization.get_by_api_key(org_key)
                    if org:
                        _org_id = org["id"]
                except Exception:
                    logger.debug("Org key resolution failed in audit middleware", exc_info=True)

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
            # Correlates the audit row with the structured log lines. The id
            # comes from the response header (set by the inner RequestID
            # middleware): contextvars set inside BaseHTTPMiddleware.call_next
            # do not propagate back to this outer task.
            "request_id": response.headers.get("x-request-id") or _request_id_var.get() or None,
        }

        db = _get_db()
        if db:
            done = _get_writer().submit(
                {
                    "action": method,
                    "user_id": _user_id,
                    "resource_type": "api",
                    "resource_id": path,
                    "details": details,
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "severity": "default",
                    "org_id": _org_id,
                    "database": db,
                }
            )
            if done is not None:
                # Off the event loop; bounded so a slow writer adds at most
                # _AUDIT_WRITE_WAIT_SECONDS to a response.
                await asyncio.to_thread(done.wait, _AUDIT_WRITE_WAIT_SECONDS)

        logger.info("API %s %s - %s (%.3fs) user=%s", method, path, status_code, duration, _user_id)

        return response
