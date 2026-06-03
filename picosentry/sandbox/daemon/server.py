"""PicoDome Daemon — HTTP API server for sandbox-as-a-service.

Uses Python's built-in ``http.server`` for zero-dependency deployment.
No Flask, no FastAPI — PicoDome stays dependency-free at runtime.

Endpoints:

    GET  /health                 — Health check (unauthenticated)
    GET  /ready                  — Readiness probe
    POST /api/v1/scan            — Submit a sandbox scan job
    GET  /api/v1/scan/:id        — Get scan result by ID
    GET  /api/v1/scans           — List recent scans
    GET  /api/v1/policies        — List policies
    GET  /api/v1/policies/:name  — Get policy detail
    POST /api/v1/policies        — Create/update a policy
    GET  /api/v1/baselines       — List baselines
    GET  /api/v1/audit           — Query audit log
    GET  /api/v1/stats           — System statistics
    GET  /metrics                — Prometheus-format metrics

Authentication: Bearer token via ``Authorization`` header.
Tokens are validated against ``PICODOME_API_TOKENS`` (comma-separated)
or a tokens file at ``~/.picodome/api-tokens``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import signal
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from picosentry.sandbox.daemon.sqlite_store import SQLiteScanJobStore
from urllib.parse import parse_qs, urlparse

from picosentry.sandbox import __version__
from picosentry.sandbox.audit import AuditEventType, get_audit_logger
from picosentry.sandbox.auth import RBAC, TokenAuth
from picosentry.sandbox.daemon.store import PersistentScanJobStore
from picosentry.sandbox.errors import ErrorCode, ErrorCodes
from picosentry.sandbox.l3.backends.base import SandboxBackend
from picosentry.sandbox.l3.engine import sandbox_run
from picosentry.sandbox.l3.policy import default_policy, load_policy
from picosentry.sandbox.l4.engine import create_default_engine
from picosentry.sandbox.l4.profiler import profile_from_sandbox_result
from picosentry.sandbox.ratelimit import TokenBucketLimiter
from picosentry.sandbox.retention import get_retention_manager
from picosentry.sandbox.tracing import trace_daemon_request

logger = logging.getLogger("picodome.daemon")

# ─── API version ────────────────────────────────────────────────────────────

API_VERSION = "v1"

# ─── CORS Configuration ──────────────────────────────────────────────────────

CORS_ALLOW_ORIGINS = os.environ.get("PICODOME_CORS_ORIGINS", "").replace("\r", "").replace("\n", "")
CORS_ALLOW_METHODS = "GET, POST, OPTIONS"
CORS_ALLOW_HEADERS = "Content-Type, Authorization, X-Tenant, X-Request-ID"
CORS_MAX_AGE = "86400"  # 24 hours
_CORS_ALLOW_ORIGINS_LIST = [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]
_CORS_DENY_BY_DEFAULT = not _CORS_ALLOW_ORIGINS_LIST and CORS_ALLOW_ORIGINS != "*"
_ENTERPRISE_MODE = os.environ.get("PICODOME_ENTERPRISE_MODE", "").lower() in ("1", "true", "yes")

# F2: In enterprise mode, reject wildcard CORS origin
if _ENTERPRISE_MODE and CORS_ALLOW_ORIGINS == "*":
    logger.warning(
        "ENTERPRISE MODE: CORS origin is wildcard ('*'). "
        "Set PICODOME_CORS_ORIGINS to specific trusted origins for production."
    )

# ─── Scan job tracker ───────────────────────────────────────────────────────


class ScanJobStore:
    """In-memory store of recent scan jobs (bounded).

    Matches the interface of ``PersistentScanJobStore`` so the handler
    can treat both stores uniformly.
    """

    def __init__(self, max_jobs: int = 1000) -> None:
        self._jobs: dict[str, dict[str, Any]] = {}
        self._max_jobs = max_jobs

    def add(self, job_id: str, command: list[str], actor: str) -> dict[str, Any]:
        job: dict[str, Any] = {
            "job_id": job_id,
            "command": command,
            "actor": actor,
            "status": "pending",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "completed_at": None,
            "result": None,
            "error": None,
        }
        self._jobs[job_id] = job

        if len(self._jobs) > self._max_jobs:
            oldest_key = min(self._jobs, key=lambda k: str(self._jobs[k].get("created_at", "")))
            del self._jobs[oldest_key]

        return job

    def update(self, job_id: str, **kwargs: Any) -> dict[str, Any] | None:
        job = self._jobs.get(job_id)
        if job is None:
            return None
        job.update(kwargs)
        return job

    def get(self, job_id: str) -> dict[str, Any] | None:
        return self._jobs.get(job_id)

    def list_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        jobs = sorted(self._jobs.values(), key=lambda j: str(j.get("created_at", "")), reverse=True)
        return jobs[:limit]


# ─── HTTP handler ────────────────────────────────────────────────────────────


class PicoDomeHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the PicoDome daemon."""

    # ── Request size limit ──────────────────────────────────────────────

    MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10 MB

    # ── Command deny list ────────────────────────────────────────────────

    # Commands that are always rejected regardless of policy.
    # Prevents privilege escalation via the daemon API.
    # F12: Enterprise allowlist — only these commands can be submitted
    ALLOWED_COMMANDS: set[str] = {
        "echo",
        "printf",
        "cat",
        "head",
        "tail",
        "sort",
        "wc",
        "grep",
        "jq",
        "yq",
        "npm",
        "npx",
        "yarn",
        "pnpm",
        "pip",
        "pip3",
        "cargo",
        "go",
        "mvn",
        "gradle",
        "make",
        "cmake",
        "dotnet",
        "gem",
        "bundle",
        "php",
        "composer",
    }

    # F12: Non-enterprise deny list (supplementary to allowlist)
    DENIED_COMMANDS: set[str] = {
        "rm",
        "rmdir",
        "mkfs",
        "dd",
        "format",
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "passwd",
        "useradd",
        "userdel",
        "usermod",
        "groupadd",
        "groupdel",
        "iptables",
        "ip6tables",
        "nft",
        "systemctl",
        "service",
        "mount",
        "umount",
        "crontab",
        "ssh",
        "telnet",
        "nc",
        "ncat",
        "curl",
        "wget",
        "bash",
        "sh",
        "zsh",
        "fish",
        "python",
        "python3",
        "perl",
        "ruby",
        "node",
        "sudo",
        "su",
        "doas",
        "chmod",
        "chown",
        "chgrp",
        "chattr",
    }

    def _validate_command(self, command: list[str]) -> str | None:
        """Validate a scan command against allowlist/denylist.

        F12: In enterprise mode, only ALLOWED_COMMANDS are permitted.
        In non-enterprise mode, DENIED_COMMANDS are blocked.

        Returns an error message if the command is denied, None if allowed.
        """
        if not command:
            return "Empty command"
        base = command[0]
        import os as _os

        base_name = _os.path.basename(base)

        if _ENTERPRISE_MODE:
            if base_name not in self.ALLOWED_COMMANDS:
                return f"Command '{base_name}' is not in enterprise allowlist"
        else:
            if base_name in self.DENIED_COMMANDS:
                return f"Command '{base_name}' is denied by server policy"
        return None

    # Set by the server at creation time
    rbac: RBAC = RBAC()
    auth: TokenAuth = TokenAuth(rbac=rbac)
    job_store: PersistentScanJobStore | ScanJobStore | SQLiteScanJobStore = PersistentScanJobStore()
    rate_limiter: TokenBucketLimiter = TokenBucketLimiter()
    _start_time: float = time.time()
    _scan_count: int = 0
    _scan_total_ms: int = 0
    _alert_count: int = 0

    def log_message(self, format, *args):
        logger.debug("HTTP %s", format % args)

    def _generate_request_id(self) -> str:
        """Generate or retrieve a request ID for traceability.

        Uses X-Request-ID header if provided by the client,
        otherwise generates a unique ID (picodome-<uuid>).
        """
        existing_id = self.headers.get("X-Request-ID", "")
        if existing_id and len(existing_id) <= 128:
            return existing_id
        return f"picodome-{uuid.uuid4().hex[:16]}"

    def _add_common_headers(self, request_id: str) -> None:
        """Add common response headers: request ID, CORS, server info."""
        self.send_header("X-Request-ID", request_id)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        # CORS headers — deny-by-default.
        # Without PICODOME_CORS_ORIGINS set, no origins are allowed.
        # Set PICODOME_CORS_ORIGINS=http://localhost:3000 or =* to enable.
        request_origin = self.headers.get("Origin", "")
        if _CORS_DENY_BY_DEFAULT:
            # No origins configured — deny all CORS
            self.send_header("Access-Control-Allow-Origin", "null")
        elif CORS_ALLOW_ORIGINS == "*":
            # Wildcard — allow any origin (not recommended for production)
            if request_origin:
                self.send_header("Access-Control-Allow-Origin", request_origin)
                self.send_header("Vary", "Origin")
            else:
                self.send_header("Access-Control-Allow-Origin", "*")
        elif request_origin in _CORS_ALLOW_ORIGINS_LIST:
            # Specific origins configured — only allow known origins
            self.send_header("Access-Control-Allow-Origin", request_origin)
            self.send_header("Vary", "Origin")
        else:
            # Request origin not in allow list — deny CORS
            self.send_header("Access-Control-Allow-Origin", "null")
        self.send_header("Access-Control-Allow-Methods", CORS_ALLOW_METHODS)
        self.send_header("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS)
        self.send_header("Access-Control-Max-Age", CORS_MAX_AGE)
        self.send_header("Access-Control-Expose-Headers", "X-Request-ID")

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        request_id = getattr(self, "_request_id", "")
        if request_id:
            self.send_header("X-Request-ID", request_id)
        self.end_headers()
        self.wfile.write(body)

    def _send_error(
        self,
        status_or_code: int | ErrorCode,
        message_or_code: str | ErrorCode | None = None,
        detail: str | None = None,
    ) -> None:
        """Send a JSON error response.

        Supports two calling conventions:
        1. _send_error(400, "Bad request")  — legacy
        2. _send_error(ErrorCodes.INVALID_JSON) — structured
        3. _send_error(ErrorCodes.COMMAND_DENIED, detail="rm is blocked") — structured with detail
        """
        if isinstance(status_or_code, ErrorCode):
            code = status_or_code
            status = code.status
            message = code.message
            if isinstance(message_or_code, str):
                detail = message_or_code  # second arg is detail when first is ErrorCode
        elif isinstance(message_or_code, ErrorCode):
            # _send_error(int, ErrorCode) — shouldn't happen but handle
            code = message_or_code
            status = status_or_code
            message = code.message
        else:
            status = status_or_code
            message = message_or_code or "Unknown error"
            code = None

        response = {
            "error": message,
            "status": status,
        }
        if code:
            response["code"] = code.key
        if detail:
            response["detail"] = detail

        self._send_json(response, status)

    def _get_token(self) -> str | None:
        """Extract bearer token from Authorization header."""
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        return None

    def _resolve_tenant(self, token: str | None) -> Any:
        """Resolve the tenant for this request.

        Uses X-Tenant header and token-to-tenant mapping from the
        TenantRegistry. Falls back to DEFAULT_TENANT.

        F6: X-Tenant header is only respected after successful auth.
        Unauthenticated requests always resolve to DEFAULT_TENANT.

        Returns:
            TenantId for this request.
        """
        from picosentry.sandbox.tenant import get_tenant_registry

        registry = get_tenant_registry()
        header_tenant = self.headers.get("X-Tenant")

        # F6: Only resolve tenant from header if authenticated
        if not token or token == "no-auth-dev-mode":
            return registry.resolve_tenant("", header_tenant=None)

        # Resolve token hash for mapping
        token_hash = ""
        if token and token != "no-auth-dev-mode":
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

        return registry.resolve_tenant(token_hash, header_tenant=header_tenant)

    def _require_auth(self) -> str | None:
        """Validate authentication. Returns token or sends 401.

        Emits AUTH_SUCCESS or AUTH_FAILURE audit events for every auth attempt.
        Emits RATE_LIMITED when an actor exceeds their rate limit.
        """
        token = self._get_token()

        if not self.auth.is_configured:
            # F1/F6: In enterprise mode, never allow dev-mode bypass
            if _ENTERPRISE_MODE:
                try:
                    audit = get_audit_logger()
                    audit.record(
                        event_type=AuditEventType.AUTH_FAILURE,
                        actor="anonymous",
                        detail="No auth configured in enterprise mode — rejecting",
                    )
                except Exception:
                    pass
                self._send_error(ErrorCodes.UNAUTHORIZED)
                return None
            return "no-auth-dev-mode"

        if not token:
            # No token provided at all
            try:
                audit = get_audit_logger()
                audit.record(
                    event_type=AuditEventType.AUTH_FAILURE,
                    actor="anonymous",
                    detail="No Authorization header provided",
                )
            except Exception:
                pass
            self._send_error(ErrorCodes.UNAUTHORIZED)
            return None

        if not self.auth.validate(token):
            # Token provided but invalid
            actor = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
            try:
                audit = get_audit_logger()
                audit.record(
                    event_type=AuditEventType.AUTH_FAILURE,
                    actor=actor,
                    detail="Invalid token",
                )
            except Exception:
                pass
            self._send_error(ErrorCodes.UNAUTHORIZED)
            return None

        # Rate limiting
        actor = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
        if not self.rate_limiter.allow(actor=actor):
            try:
                audit = get_audit_logger()
                audit.record(
                    event_type=AuditEventType.RATE_LIMITED,
                    actor=actor,
                    detail="Request rate limit exceeded",
                )
            except Exception:
                pass
            self._send_error(ErrorCodes.RATE_LIMITED)
            return None

        # Successful auth — emit AUTH_SUCCESS
        try:
            audit = get_audit_logger()
            audit.record(
                event_type=AuditEventType.AUTH_SUCCESS,
                actor=actor,
                detail="Token authenticated",
            )
        except Exception:
            pass

        return token

    def _require_permission(self, permission: str) -> str | None:
        """Require auth + permission. Returns token or sends 403.

        Emits AUTH_FAILURE when a valid token lacks the required permission.
        """
        token = self._require_auth()
        if token is None:
            return None

        if not self.rbac.has_permission(token, permission):
            actor = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
            try:
                audit = get_audit_logger()
                audit.record(
                    event_type=AuditEventType.AUTH_FAILURE,
                    actor=actor,
                    detail=f"Insufficient permissions ({permission})",
                )
            except Exception:
                pass
            self._send_error(ErrorCodes.FORBIDDEN, detail=f"Insufficient permissions ({permission})")
            return None

        return token

    # ── GET ──────────────────────────────────────────────────────────────

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight requests."""
        self.send_response(204)
        self._add_common_headers(self._generate_request_id())
        self.end_headers()

    def do_GET(self) -> None:
        self._request_id = self._generate_request_id()
        with trace_daemon_request(method="GET", path=self.path, request_id=self._request_id):
            self._handle_get()

    def _handle_get(self) -> None:
        # Request size limit
        content_length = self.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > self.MAX_REQUEST_SIZE:
                    self._send_error(ErrorCodes.REQUEST_TOO_LARGE)
                    return
            except (ValueError, OverflowError):
                self._send_error(400, "Invalid Content-Length")
                return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = parse_qs(parsed.query)

        # Health / ready (unauthenticated)
        if path == "/health":
            # F7: Rate limit unauthenticated health/ready endpoints
            if not self.rate_limiter.allow(actor="__health__"):
                self._send_error(ErrorCodes.RATE_LIMITED)
            else:
                self._handle_health()
        elif path == "/ready":
            if not self.rate_limiter.allow(actor="__ready__"):
                self._send_error(ErrorCodes.RATE_LIMITED)
            else:
                self._handle_ready()
        elif path == "/metrics":
            # If metrics-only server, skip auth
            metrics_only = getattr(self, "_metrics_only", False)
            if metrics_only:
                self._handle_metrics()
            else:
                token = self._require_permission("scan:read")
                if token:
                    self._handle_metrics()

        # Authenticated GET endpoints
        elif path == f"/api/{API_VERSION}/scans":
            token = self._require_permission("scan:read")
            if token:
                self._handle_list_scans(query)
        elif path.startswith(f"/api/{API_VERSION}/scan/"):
            token = self._require_permission("scan:read")
            if token:
                job_id = path.split("/")[-1]
                self._handle_get_scan(job_id)
        elif path == f"/api/{API_VERSION}/policies":
            token = self._require_permission("policy:read")
            if token:
                self._handle_list_policies()
        elif path.startswith(f"/api/{API_VERSION}/policies/"):
            token = self._require_permission("policy:read")
            if token:
                name = path.split("/")[-1]
                self._handle_get_policy(name)
        elif path == f"/api/{API_VERSION}/baselines":
            token = self._require_permission("baseline:read")
            if token:
                self._handle_list_baselines()
        elif path == f"/api/{API_VERSION}/audit":
            token = self._require_permission("audit:read")
            if token:
                self._handle_audit_query(query)
        elif path == f"/api/{API_VERSION}/tenants":
            token = self._require_permission("audit:read")
            if token:
                self._handle_list_tenants()
        elif path == f"/api/{API_VERSION}/tls/config":
            token = self._require_permission("scan:read")
            if token:
                self._handle_tls_config()
        elif path == f"/api/{API_VERSION}/stats":
            token = self._require_permission("scan:read")
            if token:
                self._handle_stats()
        else:
            self._send_error(ErrorCodes.NOT_FOUND, detail=path)

    # ── POST ─────────────────────────────────────────────────────────────

    def do_POST(self) -> None:
        self._request_id = self._generate_request_id()
        with trace_daemon_request(method="POST", path=self.path, request_id=self._request_id):
            self._handle_post()

    def _handle_post(self) -> None:
        # Request size limit
        content_length = self.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > self.MAX_REQUEST_SIZE:
                    self._send_error(ErrorCodes.REQUEST_TOO_LARGE)
                    return
            except (ValueError, OverflowError):
                self._send_error(400, "Invalid Content-Length")
                return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == f"/api/{API_VERSION}/scan":
            token = self._require_permission("scan:submit")
            if token:
                self._handle_submit_scan(token)
        elif path == f"/api/{API_VERSION}/policies":
            token = self._require_permission("policy:write")
            if token:
                self._handle_create_policy(token)
        else:
            self._send_error(ErrorCodes.NOT_FOUND, detail=path)

    # ── Route handlers ───────────────────────────────────────────────────

    def _handle_health(self) -> None:
        uptime = int(time.time() - self._start_time)

        # Check Redis health
        redis_health = {}
        try:
            from picosentry.sandbox.redis_health import check_redis_health

            redis_health = check_redis_health()
        except Exception:
            redis_health = {"connected": False, "mode": "in-memory"}

        # F8: Reduce info disclosure on health endpoint
        health_data: dict[str, Any] = {
            "status": "healthy",
        }
        # Only include version and details if not in enterprise mode
        if not _ENTERPRISE_MODE:
            health_data["version"] = __version__
            health_data["api_version"] = API_VERSION
            health_data["uptime_seconds"] = uptime
            health_data["redis"] = redis_health

        self._send_json(health_data)

    def _handle_ready(self) -> None:
        # Check that sandbox backend works. In community/default mode the
        # readiness probe may degrade to the observational subprocess backend
        # so orchestration health checks still receive a concrete JSON status.
        # Enterprise mode remains fail-closed and rejects observational-only
        # backends.
        try:
            from picosentry.sandbox.l3.engine import _detect_backend

            enterprise_mode = _ENTERPRISE_MODE
            backend = _detect_backend(allow_degraded=not enterprise_mode)
            is_degraded = backend.isolation_level == "observational_only"

            if enterprise_mode and backend.isolation_level == "observational_only":
                self._send_error(
                    ErrorCodes.ENTERPRISE_ENFORCEMENT,
                    detail=f"Only '{backend.name}' backend available — install libseccomp2 (Linux) or use macOS",
                )
                return

            response = {
                "status": "ready",
                "backend": backend.name,
                "isolation_level": backend.isolation_level,
                "enforcement_guarantee": backend.enforcement_guarantee,
            }  # type: dict[str, object]
            if is_degraded:
                response["degraded"] = True
                response["warning"] = "Running in observational-only mode — no real syscall enforcement"
            self._send_json(response)
        except Exception as e:
            self._send_error(ErrorCodes.NOT_READY, detail=str(e))

    def _handle_metrics(self) -> None:
        """Prometheus-format metrics endpoint."""
        uptime = int(time.time() - self._start_time)
        avg_ms = self._scan_total_ms / max(self._scan_count, 1)

        lines = [
            "# HELP picodome_scans_total Total number of scans executed",
            "# TYPE picodome_scans_total counter",
            f"picodome_scans_total {self._scan_count}",
            "",
            "# HELP picodome_scan_duration_ms_avg Average scan duration in ms",
            "# TYPE picodome_scan_duration_ms_avg gauge",
            f"picodome_scan_duration_ms_avg {avg_ms}",
            "",
            "# HELP picodome_alerts_total Total number of alerts generated",
            "# TYPE picodome_alerts_total counter",
            f"picodome_alerts_total {self._alert_count}",
            "",
            "# HELP picodome_uptime_seconds Daemon uptime in seconds",
            "# TYPE picodome_uptime_seconds gauge",
            f"picodome_uptime_seconds {uptime}",
            "",
            "# HELP picodome_version PicoDome version info",
            "# TYPE picodome_version gauge",
            f'picodome_version{{version="{__version__}"}} 1',
        ]

        body = "\n".join(lines).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_submit_scan(self, token: str) -> None:
        """Submit a sandbox scan job."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > self.MAX_REQUEST_SIZE:
                self._send_error(ErrorCodes.REQUEST_TOO_LARGE)
                return
            # Validate Content-Type for POST endpoints
            content_type = self.headers.get("Content-Type", "")
            if content_type and "application/json" not in content_type:
                self._send_error(ErrorCodes.INVALID_JSON, detail=f"Expected application/json, got {content_type}")
                return
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError) as e:
            self._send_error(ErrorCodes.INVALID_JSON, detail=str(e))
            return

        command = data.get("command")
        if not command or not isinstance(command, list):
            self._send_error(ErrorCodes.MISSING_COMMAND)
            return

        # Command deny-list check
        deny_error = self._validate_command(command)
        if deny_error:
            # Audit the command denial
            actor = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16] if token else "unknown"
            try:
                audit = get_audit_logger()
                audit.record(
                    event_type=AuditEventType.COMMAND_DENIED,
                    actor=actor,
                    detail=deny_error,
                    target=command[0] if command else "",
                    metadata={"command": command},
                )
            except Exception:
                pass
            self._send_error(ErrorCodes.COMMAND_DENIED, detail=deny_error)
            return

        timeout = data.get("timeout", 30.0)
        data.get("policy")

        job_id = uuid.uuid4().hex
        actor = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16] if token else "unknown"

        # Resolve tenant
        tenant_id = self._resolve_tenant(token)

        self.job_store.add(job_id, command, actor)

        # Audit
        try:
            audit = get_audit_logger()
            audit.record(
                event_type=AuditEventType.SCAN_START,
                actor=actor,
                detail=f"{' '.join(command)}",
                target=command[0] if command else "",
                metadata={"job_id": job_id, "timeout": timeout, "tenant_id": str(tenant_id)},
            )
        except Exception:
            pass

        try:
            # Resolve policy
            policy_name = data.get("policy")
            if policy_name:
                try:
                    policy = load_policy(name=policy_name)
                except Exception:
                    logger.warning("Policy '%s' not found, using default", policy_name)
                    policy = default_policy()
            else:
                policy = default_policy()

            # Resolve backend
            backend_name = data.get("backend", "auto")
            backend: SandboxBackend | None = None
            # F14: Block subprocess backend in enterprise mode
            if _ENTERPRISE_MODE and backend_name == "subprocess":
                self._send_error(ErrorCodes.ENTERPRISE_ENFORCEMENT, detail="subprocess backend is not allowed in enterprise mode")
                return
            if backend_name != "auto":
                backend_map = {
                    "subprocess": "picodome.l3.backends.subprocess_backend:SubprocessBackend",
                    "seccomp-bpf": "picodome.l3.backends.seccomp_backend:SeccompBackend",
                    "seatbelt": "picodome.l3.backends.seatbelt_backend:SeatbeltBackend",
                }
                cls_path = backend_map.get(backend_name)
                if cls_path is None:
                    self._send_error(ErrorCodes.INVALID_BACKEND, detail=backend_name)
                    return
                try:
                    module_path, cls_name = cls_path.rsplit(":", 1)

                    backend_cls = getattr(import_module(module_path), cls_name)
                    backend = backend_cls()
                    if not backend.is_available():
                        self._send_error(ErrorCodes.BACKEND_UNAVAILABLE, detail=backend_name)
                        return
                except Exception as e:
                    self._send_error(ErrorCodes.BACKEND_UNAVAILABLE, detail=str(e))
                    return

            # Run sandbox
            sandbox_result = sandbox_run(
                command=command,
                policy=policy,
                timeout=timeout,
                backend=backend,
                deterministic=False,
            )

            # Run L4 analysis
            engine = create_default_engine()
            profile = profile_from_sandbox_result(sandbox_result)
            analysis_result = engine.analyze(profile, deterministic=False)

            # Build result
            result = {
                "job_id": job_id,
                "sandbox": sandbox_result.to_dict(deterministic=False),
                "analysis": analysis_result.to_dict(deterministic=False),
                "l3_verdict": sandbox_result.overall_verdict.value,
                "l4_verdict": analysis_result.overall_verdict.value,
                "findings_count": len(analysis_result.findings),
                "backend": sandbox_result.backend_name,
                "isolation_level": sandbox_result.isolation_level,
                "enforcement_guarantee": sandbox_result.enforcement_guarantee,
                "degraded": sandbox_result.degraded,
                "policy_name": policy.name,
                "policy_version": policy.version,
            }

            self.job_store.update(
                job_id,
                status="completed",
                completed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                result=result,
            )

            # Update metrics
            self._scan_count += 1
            self._scan_total_ms += sandbox_result.duration_ms
            self._alert_count += len(analysis_result.findings)

            # Audit
            try:
                audit = get_audit_logger()
                audit.record(
                    event_type=AuditEventType.SCAN_COMPLETE,
                    actor=actor,
                    detail=f"l3={sandbox_result.overall_verdict.value} l4={analysis_result.overall_verdict.value}",
                    target=command[0] if command else "",
                    metadata={"job_id": job_id, "findings": len(analysis_result.findings)},
                )
            except Exception:
                pass

            # Persist result
            try:
                rm = get_retention_manager()
                rm.save_scan_result(
                    json.dumps(result, sort_keys=True, default=str),
                    package_name=command[0] if command else "unknown",
                )
            except Exception:
                pass

            self._send_json(result, status=201)

        except Exception as e:
            self.job_store.update(
                job_id,
                status="failed",
                completed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                error=str(e),
            )
            logger.exception("Scan job %s failed", job_id)
            self._send_error(ErrorCodes.SCAN_FAILED, detail=str(e))

    def _handle_get_scan(self, job_id: str) -> None:
        job = self.job_store.get(job_id)
        if job:
            self._send_json(job)
        else:
            self._send_error(ErrorCodes.SCAN_NOT_FOUND, detail=job_id)

    def _handle_list_scans(self, query: dict) -> None:
        limit = int(query.get("limit", ["50"])[0])
        jobs = self.job_store.list_recent(limit=limit)
        self._send_json(
            {
                "scans": jobs,
                "count": len(jobs),
            }
        )

    def _handle_list_policies(self) -> None:
        from picosentry.sandbox.policy_versioned import get_policy_store

        store = get_policy_store()
        names = store.list_policies()
        self._send_json({"policies": names, "count": len(names)})

    def _handle_get_policy(self, name: str) -> None:
        from picosentry.sandbox.policy_versioned import get_policy_store

        store = get_policy_store()
        pv = store.load(name)
        if pv:
            self._send_json(pv.to_dict())
        else:
            self._send_error(ErrorCodes.POLICY_NOT_FOUND, detail=name)

    def _handle_create_policy(self, token: str) -> None:
        """Create or update a policy."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            content_type = self.headers.get("Content-Type", "")
            if content_type and "application/json" not in content_type:
                self._send_error(ErrorCodes.INVALID_JSON, detail=f"Expected application/json, got {content_type}")
                return
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError) as e:
            self._send_error(ErrorCodes.INVALID_JSON, detail=str(e))
            return

        from picosentry.sandbox.l3.policy import _policy_from_dict
        from picosentry.sandbox.policy_versioned import get_policy_store

        try:
            policy = _policy_from_dict(data)
            store = get_policy_store()
            author = data.get("author", hashlib.sha256(token.encode("utf-8")).hexdigest()[:16] if token else "unknown")
            description = data.get("change_description", "")
            pv = store.save(policy, author=author, change_description=description)
            self._send_json(pv.to_dict(), status=201)
        except Exception as e:
            self._send_error(ErrorCodes.INVALID_POLICY, detail=str(e))

    def _handle_list_baselines(self) -> None:
        from picosentry.sandbox.l4.baseline import load_all_baselines

        baselines = load_all_baselines()
        self._send_json(
            {
                "baselines": {k: v.to_dict() for k, v in baselines.items()},
                "count": len(baselines),
            }
        )

    def _handle_audit_query(self, query: dict) -> None:
        from picosentry.sandbox.audit import AuditEventType, get_audit_logger

        audit = get_audit_logger()

        event_type = None
        if "event_type" in query:
            try:
                event_type = AuditEventType(query["event_type"][0])
            except ValueError:
                pass

        events = audit.query(
            event_type=event_type,
            actor=query.get("actor", [None])[0],
            target=query.get("target", [None])[0],
            since=query.get("since", [None])[0],
            until=query.get("until", [None])[0],
            limit=int(query.get("limit", ["100"])[0]),
        )
        self._send_json(
            {
                "events": [e.to_dict() for e in events],
                "count": len(events),
            }
        )

    def _handle_list_tenants(self) -> None:
        """List registered tenants (admin endpoint)."""
        from picosentry.sandbox.tenant import get_tenant_registry

        registry = get_tenant_registry()
        tenants = registry.list_tenants()
        self._send_json(
            {
                "tenants": [
                    {
                        "tenant_id": str(ctx.tenant_id),
                        "display_name": ctx.display_name,
                        "is_default": ctx.is_default,
                    }
                    for ctx in tenants
                ],
                "count": len(tenants),
            }
        )

    def _handle_tls_config(self) -> None:
        """Return current TLS/mTLS configuration (no secrets exposed)."""
        from picosentry.sandbox.mtls import get_tls_config_info

        config_info = get_tls_config_info()
        self._send_json(config_info)

    def _handle_stats(self) -> None:
        rm = get_retention_manager()
        storage = rm.get_storage_stats()
        audit = get_audit_logger()
        audit_stats = audit.get_stats()

        # F8: Reduce info disclosure on stats endpoint in enterprise mode
        stats_data: dict[str, Any] = {
            "scans_total": self._scan_count,
            "scans_avg_ms": self._scan_total_ms / max(self._scan_count, 1),
            "alerts_total": self._alert_count,
        }
        if not _ENTERPRISE_MODE:
            stats_data["version"] = __version__
            stats_data["uptime_seconds"] = int(time.time() - self._start_time)
            stats_data["storage"] = storage
            stats_data["audit"] = audit_stats

        self._send_json(stats_data)


# ─── Daemon class ────────────────────────────────────────────────────────────


class PicoDomeDaemon:
    """PicoDome daemon — HTTP API server for sandbox-as-a-service.

    Usage::

        daemon = PicoDomeDaemon(host="127.0.0.1", port=8443)
        daemon.start()   # blocking
        # or
        daemon.start(background=True)

    Configuration:
        - ``PICODOME_DAEMON_HOST`` — bind address (default: 127.0.0.1)
        - ``PICODOME_DAEMON_PORT`` — bind port (default: 8443)
        - ``PICODOME_METRICS_PORT`` — separate metrics port (default: None, same as API)
        - ``PICODOME_API_TOKENS`` — comma-separated auth tokens
        - ``PICODOME_JOB_STORE_DIR`` — directory for persistent job storage
        - ``PICODOME_AUDIT_SINKS`` — comma-separated sink types (default: null)
          Available: null, file, webhook, syslog
        - ``PICODOME_WEBHOOK_URL`` — URL for webhook sink
        - ``PICODOME_WEBHOOK_TOKEN`` — Bearer token for webhook sink
        - ``PICODOME_SYSLOG_HOST`` — Syslog server host (default: 127.0.0.1)
        - ``PICODOME_SYSLOG_PORT`` — Syslog server port (default: 514)
        - ``PICODOME_FILE_SINK_DIR`` — Directory for file sink output
        - ``PICODOME_GLOBAL_RPS`` — global requests per second across all actors (default: 25.0)
        - ``PICODOME_RATE_PER_SECOND`` — per-actor requests per second (default: 2.0)
        - ``PICODOME_STORE_BACKEND`` — job store backend: jsonl (default) or sqlite
        - ``PICODOME_SQLITE_PATH`` — path to SQLite database (default: ~/.picodome/jobs.db)
        - ``PICODOME_CORS_ORIGINS`` — allowed CORS origins (default: *)
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        metrics_port: int | None = None,
        job_store_dir: str | None = None,
        store_backend: str | None = None,
    ) -> None:
        self._host = host or os.environ.get("PICODOME_DAEMON_HOST", "127.0.0.1")
        self._port = port or int(os.environ.get("PICODOME_DAEMON_PORT", "8443"))
        self._metrics_port = metrics_port or (
            int(os.environ["PICODOME_METRICS_PORT"]) if "PICODOME_METRICS_PORT" in os.environ else None
        )
        self._server: HTTPServer | None = None
        self._metrics_server: HTTPServer | None = None
        self._job_store_dir = job_store_dir or os.environ.get("PICODOME_JOB_STORE_DIR")
        self._store_backend = store_backend or os.environ.get("PICODOME_STORE_BACKEND", "jsonl")

        # Set up job store backend (jsonl or sqlite)
        from pathlib import Path as _Path

        backend = self._store_backend.lower()
        if backend == "sqlite":
            from picosentry.sandbox.daemon.sqlite_store import SQLiteScanJobStore

            db_path = os.environ.get("PICODOME_SQLITE_PATH")
            PicoDomeHandler.job_store = SQLiteScanJobStore(
                db_path=_Path(db_path) if db_path else None,
            )
            logger.info("Using SQLite job store backend")
        else:
            from picosentry.sandbox.daemon.store import PersistentScanJobStore

            store_dir = _Path(self._job_store_dir) if self._job_store_dir else None
            PicoDomeHandler.job_store = PersistentScanJobStore(store_dir=store_dir)
            logger.info("Using JSONL job store backend")

        # Set up rate limiter from environment
        from picosentry.sandbox.ratelimit import RateLimitConfig

        global_rps = float(os.environ.get("PICODOME_GLOBAL_RPS", "25.0"))
        rate_per_second = float(os.environ.get("PICODOME_RATE_PER_SECOND", "2.0"))
        PicoDomeHandler.rate_limiter = TokenBucketLimiter(
            RateLimitConfig(
                rate_per_second=rate_per_second,
                global_rps=global_rps,
            )
        )

        # Set up audit sinks
        self._sinks = self._init_sinks()

    def _init_sinks(self) -> list:
        """Initialize audit sinks from environment configuration."""
        from picosentry.sandbox.audit.sinks import (
            AuditSink,
            FileSink,
            NullSink,
            SinkConfig,
            SyslogSink,
            WebhookSink,
        )

        sink_types = os.environ.get("PICODOME_AUDIT_SINKS", "null").split(",")
        sink_types = [s.strip().lower() for s in sink_types if s.strip()]

        sinks: list[AuditSink] = []
        for sink_type in sink_types:
            config = SinkConfig()
            try:
                if sink_type == "null":
                    sinks.append(NullSink(config=config))
                elif sink_type == "file":
                    sink_dir = os.environ.get("PICODOME_FILE_SINK_DIR")
                    sinks.append(
                        FileSink(
                            config=config,
                            output_dir=sink_dir,
                        )
                    )
                elif sink_type == "webhook":
                    url = os.environ.get("PICODOME_WEBHOOK_URL", "")
                    token = os.environ.get("PICODOME_WEBHOOK_TOKEN")
                    if not url:
                        logger.warning("WebhookSink: PICODOME_WEBHOOK_URL not set, skipping")
                        continue
                    sinks.append(
                        WebhookSink(
                            config=config,
                            url=url,
                            auth_token=token,
                        )
                    )
                elif sink_type == "syslog":
                    syslog_host = os.environ.get("PICODOME_SYSLOG_HOST", "127.0.0.1")
                    syslog_port = int(os.environ.get("PICODOME_SYSLOG_PORT", "514"))
                    sinks.append(
                        SyslogSink(
                            config=config,
                            host=syslog_host,
                            port=syslog_port,
                        )
                    )
                else:
                    logger.warning("Unknown audit sink type: '%s', skipping", sink_type)
            except Exception as exc:
                logger.warning("Failed to initialize sink '%s': %s", sink_type, exc)

        logger.info("Initialized %d audit sink(s): %s", len(sinks), [s.name for s in sinks])
        return sinks

    def start(self, background: bool = False) -> None:
        """Start the daemon HTTP server."""
        from picosentry.sandbox.mtls import create_ssl_context

        server = HTTPServer((self._host, self._port), PicoDomeHandler)
        ssl_ctx = create_ssl_context()
        if ssl_ctx:
            server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
            logger.info("mTLS: TLS enabled on %s:%d", self._host, self._port)
        self._server = server

        # Audit
        try:
            audit = get_audit_logger()
            # Wire sinks into the audit logger
            for sink in self._sinks:
                try:
                    sink.start()
                    audit.add_sink(sink)
                except Exception as exc:
                    logger.warning("Failed to start sink %s: %s", sink.name, exc)
            audit.record(
                event_type=AuditEventType.DAEMON_START,
                actor="picodome-daemon",
                detail=f"Listening on {self._host}:{self._port}",
            )
        except Exception:
            pass

        logger.info("PicoDome daemon starting on %s:%d", self._host, self._port)

        # If metrics port is separate, start a metrics-only listener
        if self._metrics_port and self._metrics_port != self._port:
            metrics_handler = type(
                "MetricsHandler",
                (PicoDomeHandler,),
                {"_metrics_only": True},
            )
            self._metrics_server = HTTPServer((self._host, self._metrics_port), metrics_handler)
            logger.info(
                "Metrics endpoint on separate port %s:%d (no auth required)",
                self._host,
                self._metrics_port,
            )
            if background:
                import threading

                metrics_thread = threading.Thread(target=self._metrics_server.serve_forever, daemon=True)
                metrics_thread.start()
            else:
                import threading

                metrics_thread = threading.Thread(target=self._metrics_server.serve_forever, daemon=True)
                metrics_thread.start()

        if background:
            import threading

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
        else:
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                self.stop()

    def stop(self) -> None:
        """Stop the daemon gracefully.

        Shuts down HTTP servers, stops audit sinks, and records a
        DAEMON_STOP audit event. Safe to call multiple times.
        """
        if self._server:
            self._server.shutdown()

        if self._metrics_server:
            self._metrics_server.shutdown()

        # Stop audit sinks
        for sink in self._sinks:
            try:
                sink.stop()
            except Exception as exc:
                logger.warning("Failed to stop sink %s: %s", sink.name, exc)

        try:
            audit = get_audit_logger()
            audit.record(
                event_type=AuditEventType.DAEMON_STOP,
                actor="picodome-daemon",
                detail="Daemon stopped",
            )
        except Exception:
            pass

        logger.info("PicoDome daemon stopped")

    def install_signal_handlers(self) -> None:
        """Install SIGTERM and SIGINT handlers for graceful shutdown.

        Call before start() when running in the foreground to ensure
        the daemon shuts down cleanly on termination signals.

        Usage::

            daemon = PicoDomeDaemon()
            daemon.install_signal_handlers()
            daemon.start()  # blocks; SIGTERM triggers graceful shutdown
        """

        def _handle_shutdown(signum: int, frame: Any) -> None:
            sig_name = signal.Signals(signum).name
            logger.info("Received %s, shutting down gracefully...", sig_name)
            self.stop()

        signal.signal(signal.SIGTERM, _handle_shutdown)
        signal.signal(signal.SIGINT, _handle_shutdown)

        # SIGHUP for config reload (graceful — reloads audit sinks and TLS certs)
        if hasattr(signal, "SIGHUP"):

            def _handle_hup(signum: int, frame: Any) -> None:
                logger.info("Received SIGHUP — reloading configuration")
                try:
                    from picosentry.sandbox.mtls import reload_ssl_context

                    ctx = reload_ssl_context()
                    if ctx and self._server:
                        self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
                        logger.info("SIGHUP: TLS context reloaded")
                except Exception as exc:
                    logger.warning("SIGHUP reload failed: %s", exc)

            signal.signal(signal.SIGHUP, _handle_hup)


def create_app(
    host: str | None = None,
    port: int | None = None,
    metrics_port: int | None = None,
    job_store_dir: str | None = None,
    store_backend: str | None = None,
    tokens: str | None = None,
    background: bool = False,
) -> PicoDomeDaemon:
    """Factory function to create an PicoDomeDaemon instance.

    Convenience wrapper around ``PicoDomeDaemon`` constructor for
    programmatic use (testing, WSGI adapters, orchestration).

    Args:
        host: Bind address (default: ``PICODOME_DAEMON_HOST`` env or ``127.0.0.1``).
        port: Bind port (default: ``PICODOME_DAEMON_PORT`` env or ``8443``).
        metrics_port: Separate metrics port (default: ``PICODOME_METRICS_PORT`` env).
        job_store_dir: Directory for persistent job storage.
        store_backend: Store backend type (``jsonl`` or ``sqlite``).
        tokens: Comma-separated API tokens (sets ``PICODOME_API_TOKENS`` env).
        background: If true, start the daemon in a background thread.

    Returns:
        Configured ``PicoDomeDaemon`` instance (started if *background* is True).
    """
    if tokens:
        os.environ["PICODOME_API_TOKENS"] = tokens

    daemon = PicoDomeDaemon(
        host=host,
        port=port,
        metrics_port=metrics_port,
        job_store_dir=job_store_dir,
        store_backend=store_backend,
    )

    if background:
        daemon.start(background=True)

    return daemon
