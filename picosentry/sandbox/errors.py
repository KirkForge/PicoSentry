"""PicoDome structured error codes.

Every API error response includes a machine-readable error code plus a
human-readable message.  This makes programmatic error handling reliable
and avoids string matching on error messages.

Usage in handlers::

    self._send_error(400, ErrorCodes.INVALID_JSON)
    self._send_error(403, ErrorCodes.COMMAND_DENIED, detail="rm is blocked")

Response format::

    {
        "error": "invalid_json",
        "code": "INVALID_JSON",
        "status": 400,
        "detail": null
    }
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ErrorCode:
    """Structured error code with HTTP status, machine key, and default message."""

    status: int
    key: str
    message: str


class ErrorCodes:
    """Central registry of all PicoDome API error codes."""

    # ── 400 Bad Request ────────────────────────────────────────────────
    INVALID_JSON = ErrorCode(400, "INVALID_JSON", "Invalid JSON body")
    MISSING_COMMAND = ErrorCode(400, "MISSING_COMMAND", "Missing or invalid 'command' field")
    INVALID_BACKEND = ErrorCode(400, "INVALID_BACKEND", "Unknown backend name")
    INVALID_POLICY = ErrorCode(400, "INVALID_POLICY", "Invalid policy definition")

    # ── 401 Unauthorized ──────────────────────────────────────────────
    UNAUTHORIZED = ErrorCode(401, "UNAUTHORIZED", "Invalid or missing token")

    # ── 403 Forbidden ─────────────────────────────────────────────────
    FORBIDDEN = ErrorCode(403, "FORBIDDEN", "Insufficient permissions")
    COMMAND_DENIED = ErrorCode(403, "COMMAND_DENIED", "Command denied by server policy")
    ENTERPRISE_ENFORCEMENT = ErrorCode(403, "ENTERPRISE_ENFORCEMENT", "Enterprise mode requires enforcement backend")

    # ── 404 Not Found ──────────────────────────────────────────────────
    NOT_FOUND = ErrorCode(404, "NOT_FOUND", "Resource not found")
    SCAN_NOT_FOUND = ErrorCode(404, "SCAN_NOT_FOUND", "Scan job not found")
    POLICY_NOT_FOUND = ErrorCode(404, "POLICY_NOT_FOUND", "Policy not found")

    # ── 413 Payload Too Large ──────────────────────────────────────────
    REQUEST_TOO_LARGE = ErrorCode(413, "REQUEST_TOO_LARGE", "Request body exceeds size limit")

    # ── 429 Too Many Requests ──────────────────────────────────────────
    RATE_LIMITED = ErrorCode(429, "RATE_LIMITED", "Rate limit exceeded")

    # ── 500 Internal Server Error ──────────────────────────────────────
    SCAN_FAILED = ErrorCode(500, "SCAN_FAILED", "Scan execution failed")
    INTERNAL_ERROR = ErrorCode(500, "INTERNAL_ERROR", "Internal server error")

    # ── 503 Service Unavailable ────────────────────────────────────────
    NOT_READY = ErrorCode(503, "NOT_READY", "Service not ready")
    BACKEND_UNAVAILABLE = ErrorCode(503, "BACKEND_UNAVAILABLE", "Requested backend unavailable")
