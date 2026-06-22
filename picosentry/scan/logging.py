from __future__ import annotations

import json
import logging
import sys
import threading
from datetime import datetime, timezone


_request_context = threading.local()


def set_request_context(request_id: str = "", actor: str = "") -> None:
    _request_context.request_id = request_id
    _request_context.actor = actor


def get_request_id() -> str:
    return getattr(_request_context, "request_id", "")


def get_actor() -> str:
    return getattr(_request_context, "actor", "")


def clear_request_context() -> None:
    _request_context.request_id = ""
    _request_context.actor = ""


class JsonFormatter(logging.Formatter):
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

        for key in self._PROMOTED_FIELDS:
            val = getattr(record, key, None)
            if val is not None:
                log_entry[key] = val

        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            log_entry.update(record.extra_fields)

        request_id = get_request_id()
        if request_id and "request_id" not in log_entry:
            log_entry["request_id"] = request_id

        actor = get_actor()
        if actor and "actor" not in log_entry:
            log_entry["actor"] = actor

        return json.dumps(log_entry, sort_keys=True)


class AuditLogFormatter(JsonFormatter):
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

        for key in ("scan_id", "corpus_version", "engine_version", "duration_ms", "findings_count", "packages_scanned"):
            val = getattr(record, key, None)
            if val is not None:
                log_entry[key] = val
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            log_entry.update(record.extra_fields)

        request_id = get_request_id()
        if request_id and "request_id" not in log_entry:
            log_entry["request_id"] = request_id
        return json.dumps(log_entry, sort_keys=True)


_audit_logger = logging.getLogger("picosentry.audit")


def configure_logging(log_format: str = "text", level: int = logging.INFO) -> None:
    root = logging.getLogger("picosentry")
    root.setLevel(level)

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
    return _audit_logger
