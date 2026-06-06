"""
PicoDome structured logging — JSON formatter for SIEM integration.

Provides two formatters:
- PicoDomeTextFormatter: Human-readable text (default)
- PicoDomeJSONFormatter: Structured JSON for SIEM/log aggregation

Controlled by --log-format and --verbose CLI flags.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, ClassVar

# Module-level version for log output
try:
    from picosentry.sandbox import __version__
except ImportError:
    __version__ = "2.0.1"


class PicoDomeJSONFormatter(logging.Formatter):
    """
    Structured JSON formatter for SIEM/log aggregation systems.

    Outputs one JSON object per line (NDJSON). Each log record includes:
    - timestamp (ISO 8601 UTC)
    - level (INFO, WARNING, ERROR, etc.)
    - logger name
    - message
    - picodome_version
    - Any extra fields passed via logger.info(..., extra={...})

    Deterministic: timestamp uses UTC, no random IDs.
    """

    def __init__(self, include_version: bool = True):
        super().__init__()
        self.include_version = include_version

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as a single-line JSON object."""
        entry: dict[str, Any] = {
            "timestamp": self._format_time(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if self.include_version:
            entry["picodome_version"] = __version__

        # Include any extra fields
        if hasattr(record, "picodome_context") and isinstance(record.picodome_context, dict):
            entry.update(record.picodome_context)

        # Include exception info if present
        if record.exc_info and record.exc_text is None:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            entry["exception"] = record.exc_text

        # Deterministic key ordering
        return json.dumps(entry, sort_keys=True, default=str)

    def _format_time(self, record: logging.LogRecord) -> str:
        """Format timestamp as ISO 8601 UTC."""
        try:
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created))
        except (AttributeError, OSError):
            return f"{record.created:.3f}"


class PicoDomeTextFormatter(logging.Formatter):
    """
    Human-readable text formatter for console output.

    Format: [LEVEL] logger: message
    With optional color codes (disabled by --no-color or PICODOME_NO_COLOR).
    """

    # ANSI color codes
    COLORS: ClassVar[dict[str, str]] = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[1;31m",  # Bold red
    }
    RESET = "\033[0m"

    def __init__(self, use_color: bool = True, verbose: bool = False):
        """
        Args:
            use_color: Whether to use ANSI color codes.
            verbose: Whether to include logger name in output.
        """
        if verbose:
            fmt = "[%(levelname)s] %(name)s: %(message)s"
        else:
            fmt = "[%(levelname)s] %(message)s"
        super().__init__(fmt=fmt)
        self.use_color = use_color
        self.verbose = verbose

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record with optional color codes."""
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
    """
    Configure PicoDome logging.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_format: Output format — "text" (human-readable) or "json" (SIEM).
        use_color: Whether to use ANSI color codes in text output.
        verbose: Whether to include logger name in text output.
    """
    root_logger = logging.getLogger("picodome")

    # Clear existing handlers
    root_logger.handlers.clear()

    # Set level
    numeric_level = getattr(logging, level.upper(), logging.WARNING)
    root_logger.setLevel(numeric_level)

    # Create handler
    handler = logging.StreamHandler()
    handler.setLevel(numeric_level)

    # Set formatter
    formatter: logging.Formatter
    if log_format == "json":
        formatter = PicoDomeJSONFormatter(include_version=True)
    else:
        formatter = PicoDomeTextFormatter(use_color=use_color, verbose=verbose)

    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

    # Prevent propagation to root logger
    root_logger.propagate = False


def get_log_context(
    command: list | None = None,
    run_id: str | None = None,
    policy: str | None = None,
    target: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Build a context dict for structured logging.

    Use with logger.info("message", extra={"picodome_context": ctx}).

    Args:
        command: Command being sandboxed.
        run_id: Unique run identifier.
        policy: Policy name.
        target: Target package/path being analyzed.
        **kwargs: Additional context fields.

    Returns:
        Dict suitable for picodome_context extra field.
    """
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
