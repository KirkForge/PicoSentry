
from __future__ import annotations

import json
import logging
import time
from typing import Any, ClassVar


try:
    from picosentry.sandbox import __version__
except ImportError:
    __version__ = "2.0.7"


class PicoDomeJSONFormatter(logging.Formatter):

    def __init__(self, include_version: bool = True):
        super().__init__()
        self.include_version = include_version

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": self._format_time(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if self.include_version:
            entry["picodome_version"] = __version__


        if hasattr(record, "picodome_context") and isinstance(record.picodome_context, dict):
            entry.update(record.picodome_context)


        if record.exc_info and record.exc_text is None:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            entry["exception"] = record.exc_text


        return json.dumps(entry, sort_keys=True, default=str)

    def _format_time(self, record: logging.LogRecord) -> str:
        try:
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created))
        except (AttributeError, OSError):
            return f"{record.created:.3f}"


class PicoDomeTextFormatter(logging.Formatter):


    COLORS: ClassVar[dict[str, str]] = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[1;31m",  # Bold red
    }
    RESET = "\033[0m"

    def __init__(self, use_color: bool = True, verbose: bool = False):
        fmt = "[%(levelname)s] %(name)s: %(message)s" if verbose else "[%(levelname)s] %(message)s"
        super().__init__(fmt=fmt)
        self.use_color = use_color
        self.verbose = verbose

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)

        if self.use_color:
            color = self.COLORS.get(record.levelname, "")
            if color:
                message = f"{color}{message}{self.RESET}"

        return message


def setup_logging(
    level: str = "WARNING",
    log_format: str = "text",
    use_color: bool = True,
    verbose: bool = False,
) -> None:
    root_logger = logging.getLogger("picodome")


    root_logger.handlers.clear()


    numeric_level = getattr(logging, level.upper(), logging.WARNING)
    root_logger.setLevel(numeric_level)


    handler = logging.StreamHandler()
    handler.setLevel(numeric_level)


    formatter: logging.Formatter
    if log_format == "json":
        formatter = PicoDomeJSONFormatter(include_version=True)
    else:
        formatter = PicoDomeTextFormatter(use_color=use_color, verbose=verbose)

    handler.setFormatter(formatter)
    root_logger.addHandler(handler)


    root_logger.propagate = False


def get_log_context(
    command: list | None = None,
    run_id: str | None = None,
    policy: str | None = None,
    target: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    ctx: dict[str, Any] = {}

    if command is not None:
        ctx["command"] = command
    if run_id is not None:
        ctx["run_id"] = run_id
    if policy is not None:
        ctx["policy"] = policy
    if target is not None:
        ctx["target"] = target

    ctx.update(kwargs)
    return ctx
