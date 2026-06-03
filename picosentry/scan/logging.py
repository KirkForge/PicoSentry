"""
Structured logging support for PicoSentry.

Provides JSON-structured log output for SIEM integration (Splunk, ELK, Datadog).
Plain text logging is the default; use --log-format json for structured output.

Supports request ID context propagation and a dedicated audit log channel.

Usage:
    from picosentry.scan.logging import configure_logging, set_request_context, get_request_id

    configure_logging(log_format="json")
    set_request_context(request_id="abc123", actor="user@example.com")
    logger.info("scan completed", extra={"scan_id": "..."})
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from datetime import datetime, timezone

# ── Thread-local request context ───────────────────────────────────────

_request_context = threading.local()


def set_request_context(request_id: str = "", actor: str = "") -> None:
    """Set the current request context for log enrichment.

    Args:
        request_id: Request ID for tracing (from daemon or CLI).
        actor: Authenticated identity (from auth module).
    """
    _request_context.request_id = request_id
    _request_context.actor = actor


def get_request_id() -> str:
    """Get the current request ID from thread-local context."""
    return getattr(_request_context, "request_id", "")


def get_actor() -> str:
    """Get the current actor from thread-local context."""
    return getattr(_request_context, "actor", "")


def clear_request_context() -> None:
    """Clear the current request context."""
    _request_context.request_id = ""
    _request_context.actor = ""


# ── JSON formatter ──────────────────────────────────────────────────────


class JsonFormatter(logging.Formatter):
    """JSON-structured log formatter for enterprise SIEM integration.

    Produces one JSON object per log line with timestamp, level, logger,
    message, and any extra fields passed via ``extra`` dict.

    Automatically includes request_id and actor from thread-local context
    when available.
    """

    # Fields that should be promoted to top-level in the JSON output
    _PROMOTED_FIELDS = frozenset(
        {
            "scan_id",
            "corpus_version",
            "engine_version",
            "duration_ms",
            "findings_count",
            "packages_scanned",
            "request_id",
            "actor",
            "action",
            "target",
            "outcome",
        }
    )

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include promoted fields from the record
        for key in self._PROMOTED_FIELDS:
            val = getattr(record, key, None)
            if val is not None:
                log_entry[key] = val

        # Include any extra dict fields
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            log_entry.update(record.extra_fields)

        # Auto-include request context from thread-local
        request_id = get_request_id()
        if request_id and "request_id" not in log_entry:
            log_entry["request_id"] = request_id

        actor = get_actor()
        if actor and "actor" not in log_entry:
            log_entry["actor"] = actor

        return json.dumps(log_entry, sort_keys=True)


class AuditLogFormatter(JsonFormatter):
    """JSON formatter specifically for audit log output.

    Always includes action, target, actor, and outcome fields.
    Used by the audit logger to write structured events.
    Constructs the dict directly to avoid double serialization.
    """

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.now(timezone.utc).isoformat()
        log_entry = {
            "timestamp": ts,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "audit": True,
            "action": getattr(record, "action", ""),
            "target": getattr(record, "target", ""),
            "actor": getattr(record, "actor", get_actor()),
            "outcome": getattr(record, "outcome", ""),
        }
        # Include any extra fields
        for key in ("scan_id", "corpus_version", "engine_version", "duration_ms", "findings_count", "packages_scanned"):
            val = getattr(record, key, None)
            if val is not None:
                log_entry[key] = val
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            log_entry.update(record.extra_fields)
        # Include request context
        request_id = get_request_id()
        if request_id and "request_id" not in log_entry:
            log_entry["request_id"] = request_id
        return json.dumps(log_entry, sort_keys=True)


# ── Logger configuration ───────────────────────────────────────────────

# Dedicated audit logger — writes to a separate handler
_audit_logger = logging.getLogger("picosentry.audit")


def configure_logging(log_format: str = "text", level: int = logging.INFO) -> None:
    """Configure root logger for the specified format.

    Args:
        log_format: "text" (default) or "json" for structured output.
        level: Logging level (default: INFO).
    """
    root = logging.getLogger("picosentry")
    root.setLevel(level)

    # Remove existing handlers
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    if log_format == "json":
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(JsonFormatter())
        root.addHandler(handler)
    else:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(levelname)s [%(name)s] %(message)s"))
        root.addHandler(handler)


def configure_audit_logging(
    path: str | None = None,
    level: int = logging.INFO,
) -> logging.Handler | None:
    """Configure the dedicated audit logger to write to a file.

    Args:
        path: Path to the audit log file. If None, audit logging is disabled.
        level: Logging level for the audit handler.

    Returns:
        The audit FileHandler, or None if path is None.
    """
    # Remove existing audit handlers
    for handler in _audit_logger.handlers[:]:
        _audit_logger.removeHandler(handler)

    if path is None:
        _audit_logger.setLevel(logging.CRITICAL + 1)  # Disable
        return None

    from pathlib import Path

    log_path = Path(path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(AuditLogFormatter())
    handler.setLevel(level)
    _audit_logger.addHandler(handler)
    _audit_logger.setLevel(level)

    return handler


def get_audit_logger() -> logging.Logger:
    """Get the dedicated audit logger."""
    return _audit_logger
