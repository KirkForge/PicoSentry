"""Scan worker process and error classes for the scan CLI service."""

from __future__ import annotations

import multiprocessing
import traceback
from pathlib import Path


class ScanTimeout(Exception):
    """Raised when a scan exceeds its ``--timeout`` budget."""


class ScanError(Exception):
    """Raised when the scan worker process reports an error."""

    def __init__(self, message: str, exc_type: str | None = None, exc_traceback: str | None = None) -> None:
        super().__init__(message)
        self.exc_type = exc_type
        self.exc_traceback = exc_traceback


def _scan_worker(
    target_path: str,
    rules: list[str] | None,
    corpus_dir: str | None,
    advisory_db_path: str | None,
    result_queue: multiprocessing.Queue,
) -> None:
    try:
        from picosentry.scan.engine import create_default_engine

        eng = create_default_engine(
            corpus_dir=Path(corpus_dir) if corpus_dir else None,
            advisory_db_path=advisory_db_path,
        )
        r = eng.scan(target_path, rules=rules, advisory_db_path=advisory_db_path)
        result_queue.put(("ok", r))
    except (OSError, RuntimeError, ValueError, TypeError, ImportError, TimeoutError) as e:
        result_queue.put(
            (
                "error",
                {
                    "type": type(e).__name__,
                    "message": str(e),
                    "traceback": traceback.format_exc(),
                },
            )
        )
