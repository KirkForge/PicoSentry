from __future__ import annotations

from dataclasses import dataclass


class PicoSentryError(Exception):
    """Base class for all serve-wide application errors."""


class AuthError(PicoSentryError):
    """Authentication or authorization failed (HTTP 401)."""


class ValidationError(PicoSentryError):
    """Request input failed validation (HTTP 422)."""


class NotFoundError(PicoSentryError):
    """Requested resource does not exist (HTTP 404)."""


class ConflictError(PicoSentryError):
    """Request conflicts with current resource state (HTTP 409)."""


class ServiceError(PicoSentryError):
    """Unexpected service failure (HTTP 500)."""


@dataclass(frozen=True)
class ServeError:
    status: int
    key: str
    message: str


class ServeErrors:
    VALIDATION_ERROR = ServeError(400, "VALIDATION_ERROR", "Invalid request")
    INVALID_CREDENTIALS = ServeError(401, "INVALID_CREDENTIALS", "Invalid or expired token")
    REGISTRATION_DISABLED = ServeError(403, "REGISTRATION_DISABLED", "Registration is disabled")
    INSUFFICIENT_PERMISSIONS = ServeError(403, "INSUFFICIENT_PERMISSIONS", "Insufficient permissions")
    FORBIDDEN_PATH = ServeError(403, "FORBIDDEN_PATH", "Target path is outside configured workspace")
    ORG_NOT_FOUND = ServeError(404, "ORG_NOT_FOUND", "Organization not found")
    PROJECT_NOT_FOUND = ServeError(404, "PROJECT_NOT_FOUND", "Project not found")
    ALERT_NOT_FOUND = ServeError(404, "ALERT_NOT_FOUND", "Alert not found")
    RULE_NOT_FOUND = ServeError(404, "RULE_NOT_FOUND", "Rule not found")
    JOB_NOT_FOUND = ServeError(404, "JOB_NOT_FOUND", "Scheduler job not found")
    API_KEY_NOT_FOUND = ServeError(404, "API_KEY_NOT_FOUND", "API key not found")
    KILL_CHAIN_NOT_FOUND = ServeError(404, "KILL_CHAIN_NOT_FOUND", "Kill-chain data not found")
    CONFLICT_USERNAME = ServeError(409, "CONFLICT_USERNAME", "Username already exists")
    CONFLICT_SLUG = ServeError(409, "CONFLICT_SLUG", "Organization slug already exists")
    SCANS_DISABLED = ServeError(503, "SCANS_DISABLED", "Scans workspace root is not configured")
    SANDBOX_FAILED = ServeError(500, "SANDBOX_FAILED", "Sandbox execution failed")
    INTERNAL_ERROR = ServeError(500, "INTERNAL_ERROR", "Internal server error")
