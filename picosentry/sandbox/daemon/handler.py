"""PicoDomeHandler — HTTP request handler composing the mixins.

Extracted in v2.1.0 (refactor) from ``picosentry/sandbox/daemon/server.py``.

The :class:`PicoDomeHandler` class is the composition of:

- :class:`~picosentry.sandbox.daemon.handler_mixins.PicoDomeResponseMixin`
- :class:`~picosentry.sandbox.daemon.handler_mixins.PicoDomeAuthMixin`
- :class:`~picosentry.sandbox.daemon.handler_routes_get.PicoDomeGetRoutesMixin`
- :class:`~picosentry.sandbox.daemon.handler_routes_post.PicoDomePostRoutesMixin`

This file holds only the class-level state (class attributes for RBAC, job
store, rate limiter, runtime counters) and the ``do_GET``/``do_POST``/
``do_OPTIONS`` HTTP-method dispatchers.
"""
from __future__ import annotations

import logging
import time
from http.server import BaseHTTPRequestHandler
from typing import TYPE_CHECKING, Any, ClassVar

from picosentry.sandbox.auth import RBAC, TokenAuth
from picosentry.sandbox.daemon.constants import API_VERSION
from picosentry.sandbox.daemon.handler_mixins import (
    PicoDomeAuthMixin,
    PicoDomeResponseMixin,
)
from picosentry.sandbox.daemon.handler_routes_get import PicoDomeGetRoutesMixin
from picosentry.sandbox.daemon.handler_routes_post import PicoDomePostRoutesMixin
from picosentry.sandbox.daemon.job_store import ScanJobStore
from picosentry.sandbox.ratelimit import TokenBucketLimiter
from picosentry.sandbox.tracing import trace_daemon_request

if TYPE_CHECKING:
    from picosentry.sandbox.daemon.sqlite_store import SQLiteScanJobStore

from picosentry.sandbox.daemon.store import PersistentScanJobStore

logger = logging.getLogger("picodome.daemon")


class PicoDomeHandler(
    PicoDomeResponseMixin,
    PicoDomeAuthMixin,
    PicoDomeGetRoutesMixin,
    PicoDomePostRoutesMixin,
    BaseHTTPRequestHandler,
):
    """HTTP request handler for the PicoDome daemon.

    Composed from four mixins:
    - ``PicoDomeResponseMixin`` — request ID, common headers, JSON responses
    - ``PicoDomeAuthMixin``     — token, tenant, auth, RBAC, command validation
    - ``PicoDomeGetRoutesMixin``  — GET endpoint handlers
    - ``PicoDomePostRoutesMixin`` — POST endpoint handlers
    """

    # ── Request size limit ──────────────────────────────────────────────

    MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10 MB
    API_VERSION = API_VERSION  # exposed as self.API_VERSION for route mixins

    # Set by the server at creation time
    rbac: RBAC = RBAC()
    auth: TokenAuth = TokenAuth(rbac=rbac)
    job_store: PersistentScanJobStore | ScanJobStore | SQLiteScanJobStore = PersistentScanJobStore()
    rate_limiter: TokenBucketLimiter = TokenBucketLimiter()
    _start_time: float = time.time()
    _scan_count: int = 0
    _scan_total_ms: int = 0
    _alert_count: int = 0

    # ── HTTP method dispatchers ─────────────────────────────────────────

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight requests."""
        self.send_response(204)
        self._add_common_headers(self._generate_request_id())
        self.end_headers()

    def do_GET(self) -> None:
        self._request_id = self._generate_request_id()
        with trace_daemon_request(method="GET", path=self.path, request_id=self._request_id):
            self._handle_get()

    def do_POST(self) -> None:
        self._request_id = self._generate_request_id()
        with trace_daemon_request(method="POST", path=self.path, request_id=self._request_id):
            self._handle_post()


__all__ = ["PicoDomeHandler"]
