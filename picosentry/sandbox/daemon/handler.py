from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler
from typing import Any

from picosentry.sandbox.auth import RBAC, TokenAuth
from picosentry.sandbox.daemon.constants import API_VERSION
from picosentry.sandbox.daemon.handler_mixins import (
    PicoDomeAuthMixin,
    PicoDomeResponseMixin,
)
from picosentry.sandbox.daemon.handler_routes_get import PicoDomeGetRoutesMixin
from picosentry.sandbox.daemon.handler_routes_post import PicoDomePostRoutesMixin
from picosentry.sandbox.errors import ErrorCodes
from picosentry.sandbox.ratelimit import TokenBucketLimiter
from picosentry.sandbox.tenant import TenantMismatchError
from picosentry.sandbox.tracing import trace_daemon_request

from picosentry.sandbox.daemon.store import PersistentScanJobStore
from picosentry.sandbox.tenant.store import TenantAwareScanJobStore

logger = logging.getLogger("picodome.daemon")


class PicoDomeHandler(
    PicoDomeResponseMixin,
    PicoDomeAuthMixin,
    PicoDomeGetRoutesMixin,
    PicoDomePostRoutesMixin,
    BaseHTTPRequestHandler,
):
    MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10 MB
    timeout = 30  # seconds; idle connection read timeout
    API_VERSION = API_VERSION  # exposed as self.API_VERSION for route mixins

    rbac: RBAC = RBAC()
    auth: TokenAuth = TokenAuth(rbac=rbac)
    # Tenant-scoped by default (WO4.0.0-010); PicoDomeDaemon replaces this with
    # a tenant-wrapped persistent store at init. Any: tests embed raw stores,
    # and the spoken contract is the TenantAwareScanJobStore API.
    job_store: Any = TenantAwareScanJobStore(PersistentScanJobStore())
    rate_limiter: TokenBucketLimiter = TokenBucketLimiter()
    # Scan worker pool (set by PicoDomeDaemon at init). None = run inline
    # (direct handler use in tests / library embedding).
    scan_executor: ThreadPoolExecutor | None = None
    scan_slots: threading.Semaphore | None = None
    _start_time: float = time.time()
    _stats_lock: threading.Lock = threading.Lock()
    _scan_count: int = 0
    _scan_total_ms: int = 0
    _alert_count: int = 0

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._add_common_headers(self._generate_request_id())
        self.end_headers()

    def do_GET(self) -> None:
        self._request_id = self._generate_request_id()
        with trace_daemon_request(method="GET", path=self.path, request_id=self._request_id):
            try:
                self._handle_get()
            except TenantMismatchError:
                self._send_error(ErrorCodes.FORBIDDEN, detail="X-Tenant does not match token's tenant")

    def do_POST(self) -> None:
        self._request_id = self._generate_request_id()
        with trace_daemon_request(method="POST", path=self.path, request_id=self._request_id):
            try:
                self._handle_post()
            except TenantMismatchError:
                self._send_error(ErrorCodes.FORBIDDEN, detail="X-Tenant does not match token's tenant")


__all__ = ["PicoDomeHandler"]
