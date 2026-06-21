import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class JSONFormatter(logging.Formatter):
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

        if hasattr(record, "request_id"):
            entry["request_id"] = record.request_id

        for attr in ("component", "project_id", "duration_ms", "status_code", "user_id", "ip"):
            val = getattr(record, attr, None)
            if val is not None:
                entry[attr] = val

        if record.exc_info and record.exc_info[1]:
            entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
            }

        if self.structured:
            return json.dumps(entry, default=str)

        return f"{entry['timestamp']} | {entry['level']:<8} | {entry['logger']} | {entry['message']}"


def configure_logging(
    level: str = "INFO",
    log_dir: Path | None = None,
    structured: bool = True,
    max_bytes: int = 10_000_000,
    backup_count: int = 10,
) -> None:
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    root_logger.handlers.clear()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(JSONFormatter(structured=structured))
    root_logger.addHandler(console_handler)

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

    for noisy in ("uvicorn", "uvicorn.access", "urllib3", "requests", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
