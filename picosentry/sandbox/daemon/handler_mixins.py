"""PicoDomeHandler auth + response mixins.

Extracted in v2.1.0 (refactor) from ``picosentry/sandbox/daemon/server.py``.

- :class:`PicoDomeResponseMixin` — request ID, common headers, JSON response
  helpers, error response helpers.
- :class:`PicoDomeAuthMixin` — token extraction, tenant resolution, auth
  enforcement, RBAC permission checks, command deny-list validation.

These mixins are combined with :class:`PicoDomeGetRoutesMixin` and
:class:`PicoDomePostRoutesMixin` to form the full
:class:`PicoDomeHandler` class.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from typing import Any, ClassVar

from picosentry.sandbox.audit import AuditEventType, get_audit_logger
from picosentry.sandbox.auth import RBAC, TokenAuth
from picosentry.sandbox.daemon.constants import (
    CORS_ALLOW_HEADERS,
    CORS_ALLOW_METHODS,
    CORS_ALLOW_ORIGINS,
    CORS_MAX_AGE,
    _CORS_ALLOW_ORIGINS_LIST,
    _CORS_DENY_BY_DEFAULT,
    _ENTERPRISE_MODE,
)
from picosentry.sandbox.errors import ErrorCode, ErrorCodes
from picosentry.sandbox.ratelimit import TokenBucketLimiter

logger = logging.getLogger("picodome.daemon")


# ─── Response mixin ─────────────────────────────────────────────────────────


class PicoDomeResponseMixin:
    """Response helpers: request ID, common headers, JSON, error responses."""

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


# ─── Auth mixin ──────────────────────────────────────────────────────────────


class PicoDomeAuthMixin:
    """Authentication, tenant resolution, and command validation."""

    # Commands that are always rejected regardless of policy.
    # Prevents privilege escalation via the daemon API.
    # F12: Enterprise allowlist — only these commands can be submitted
    ALLOWED_COMMANDS: ClassVar[set[str]] = {
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
    DENIED_COMMANDS: ClassVar[set[str]] = {
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


__all__ = [
    "PicoDomeAuthMixin",
    "PicoDomeResponseMixin",
]
