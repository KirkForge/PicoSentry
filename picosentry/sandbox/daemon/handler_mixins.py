from __future__ import annotations

import hashlib
import json
import logging
import uuid
from typing import TYPE_CHECKING, Any, ClassVar

from picosentry.sandbox.audit import AuditEventType, get_audit_logger
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

if TYPE_CHECKING:
    from picosentry.sandbox.daemon.handler import PicoDomeHandler

logger = logging.getLogger("picodome.daemon")


class PicoDomeResponseMixin:
    def log_message(self, format, *args):
        logger.debug("HTTP %s", format % args)

    def _generate_request_id(self: PicoDomeHandler) -> str:
        existing_id = self.headers.get("X-Request-ID", "")
        if existing_id and len(existing_id) <= 128:
            return existing_id
        return f"picodome-{uuid.uuid4().hex[:16]}"

    def _add_common_headers(self: PicoDomeHandler, request_id: str) -> None:
        self.send_header("X-Request-ID", request_id)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")

        request_origin = self.headers.get("Origin", "")
        if _CORS_DENY_BY_DEFAULT:
            self.send_header("Access-Control-Allow-Origin", "null")
        elif CORS_ALLOW_ORIGINS == "*":
            if request_origin:
                self.send_header("Access-Control-Allow-Origin", request_origin)
                self.send_header("Vary", "Origin")
            else:
                self.send_header("Access-Control-Allow-Origin", "*")
        elif request_origin in _CORS_ALLOW_ORIGINS_LIST:
            self.send_header("Access-Control-Allow-Origin", request_origin)
            self.send_header("Vary", "Origin")
        else:
            self.send_header("Access-Control-Allow-Origin", "null")
        self.send_header("Access-Control-Allow-Methods", CORS_ALLOW_METHODS)
        self.send_header("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS)
        self.send_header("Access-Control-Max-Age", CORS_MAX_AGE)
        self.send_header("Access-Control-Expose-Headers", "X-Request-ID")

    def _send_json(self: PicoDomeHandler, data: Any, status: int = 200) -> None:
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
        self: PicoDomeHandler,
        status_or_code: int | ErrorCode,
        message_or_code: str | ErrorCode | None = None,
        detail: str | None = None,
    ) -> None:
        if isinstance(status_or_code, ErrorCode):
            code = status_or_code
            status = code.status
            message = code.message
            if isinstance(message_or_code, str):
                detail = message_or_code  # second arg is detail when first is ErrorCode
        elif isinstance(message_or_code, ErrorCode):
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


class PicoDomeAuthMixin:
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

    def _validate_command(self: PicoDomeHandler, command: list[str]) -> str | None:
        if not command:
            return "Empty command"
        base = command[0]
        from pathlib import Path as _Path

        base_name = _Path(base).name

        if _ENTERPRISE_MODE:
            if base_name not in self.ALLOWED_COMMANDS:
                return f"Command '{base_name}' is not in enterprise allowlist"
        elif base_name in self.DENIED_COMMANDS:
            return f"Command '{base_name}' is denied by server policy"
        return None

    def _get_token(self: PicoDomeHandler) -> str | None:
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        return None

    def _resolve_tenant(self: PicoDomeHandler, token: str | None) -> Any:
        from picosentry.sandbox.tenant import get_tenant_registry

        registry = get_tenant_registry()
        header_tenant = self.headers.get("X-Tenant")

        if not token or token == "no-auth-dev-mode":
            return registry.resolve_tenant("", header_tenant=None)

        token_hash = ""
        if token and token != "no-auth-dev-mode":
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

        return registry.resolve_tenant(token_hash, header_tenant=header_tenant)

    def _require_auth(self: PicoDomeHandler) -> str | None:
        token = self._get_token()

        if not self.auth.is_configured:
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

    def _require_permission(self: PicoDomeHandler, permission: str) -> str | None:
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
