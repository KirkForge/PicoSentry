from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ErrorCode:
    status: int
    key: str
    message: str


class ErrorCodes:
    INVALID_JSON = ErrorCode(400, "INVALID_JSON", "Invalid JSON body")
    MISSING_COMMAND = ErrorCode(400, "MISSING_COMMAND", "Missing or invalid 'command' field")
    INVALID_BACKEND = ErrorCode(400, "INVALID_BACKEND", "Unknown backend name")
    INVALID_POLICY = ErrorCode(400, "INVALID_POLICY", "Invalid policy definition")

    UNAUTHORIZED = ErrorCode(401, "UNAUTHORIZED", "Invalid or missing token")

    FORBIDDEN = ErrorCode(403, "FORBIDDEN", "Insufficient permissions")
    COMMAND_DENIED = ErrorCode(403, "COMMAND_DENIED", "Command denied by server policy")
    ENTERPRISE_ENFORCEMENT = ErrorCode(403, "ENTERPRISE_ENFORCEMENT", "Enterprise mode requires enforcement backend")

    NOT_FOUND = ErrorCode(404, "NOT_FOUND", "Resource not found")
    SCAN_NOT_FOUND = ErrorCode(404, "SCAN_NOT_FOUND", "Scan job not found")
    POLICY_NOT_FOUND = ErrorCode(404, "POLICY_NOT_FOUND", "Policy not found")

    REQUEST_TOO_LARGE = ErrorCode(413, "REQUEST_TOO_LARGE", "Request body exceeds size limit")

    RATE_LIMITED = ErrorCode(429, "RATE_LIMITED", "Rate limit exceeded")

    SCAN_FAILED = ErrorCode(500, "SCAN_FAILED", "Scan execution failed")
    INTERNAL_ERROR = ErrorCode(500, "INTERNAL_ERROR", "Internal server error")

    NOT_READY = ErrorCode(503, "NOT_READY", "Service not ready")
    BACKEND_UNAVAILABLE = ErrorCode(503, "BACKEND_UNAVAILABLE", "Requested backend unavailable")
