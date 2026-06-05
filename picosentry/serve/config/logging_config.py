"""Structured JSON logging configuration for PicoShogun."""
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class JSONFormatter(logging.Formatter):
    """Emit log records as single-line JSON objects.

    Each record includes: timestamp, level, logger, message,
    plus optional fields like request_id, component, etc.
    """

    def __init__(self, structured: bool = True):
        super().__init__()
        self.structured = structured

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include request_id if attached (by RequestIDMiddleware)
        if hasattr(record, "request_id"):
            entry["request_id"] = record.request_id

        # Include any custom fields
        for attr in ("component", "project_id", "duration_ms", "status_code", "user_id", "ip"):
            val = getattr(record, attr, None)
            if val is not None:
                entry[attr] = val

        # Include exception info if present
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
            }

        if self.structured:
            return json.dumps(entry, default=str)
        else:
            # Human-readable fallback
            return f"{entry['timestamp']} | {entry['level']:<8} | {entry['logger']} | {entry['message']}"


def configure_logging(
    level: str = "INFO",
    log_dir: Path | None = None,
    structured: bool = True,
    max_bytes: int = 10_000_000,
    backup_count: int = 10,
) -> None:
    """Configure application-wide logging with structured JSON output.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_dir: Directory for log files. None = stdout only.
        structured: If True, emit JSON; if False, emit human-readable text.
        max_bytes: Max size per log file before rotation.
        backup_count: Number of rotated log files to keep.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers
    root_logger.handlers.clear()

    # Console handler (always)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(JSONFormatter(structured=structured))
    root_logger.addHandler(console_handler)

    # File handler (optional)
    if log_dir:
        from logging.handlers import RotatingFileHandler

        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_dir / "picoshogun.log",
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        file_handler.setFormatter(JSONFormatter(structured=structured))
        root_logger.addHandler(file_handler)

    # Reduce noise from third-party loggers
    for noisy in ("uvicorn", "uvicorn.access", "urllib3", "requests", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
