"""FileSink — append audit events to a JSONL file with size-based rotation.

Each event is written as a single JSON line. When the file exceeds
``max_bytes``, it's rotated to ``<name>.1.jsonl.gz``, existing rotated
files are shifted, and a fresh file is started.

This mirrors the AuditLogger's own rotation logic but outputs events
in a separate sink-specific directory (useful for forwarding to SIEMs
or external consumers that expect a simple JSONL feed).
"""

from __future__ import annotations

import gzip
import typing
import logging
import shutil
import threading
from pathlib import Path

from picosentry.sandbox.audit.logger import AuditEvent
from picosentry.sandbox.audit.sinks.base import AuditSink, SinkConfig

logger = logging.getLogger("picodome.audit.sink.file")


_DEFAULT_FILE_DIR = Path.home() / ".picodome" / "sink"
_DEFAULT_FILE_NAME = "audit_sink.jsonl"
_DEFAULT_MAX_BYTES = 50 * 1024 * 1024  # 50 MiB
_DEFAULT_ROTATE_COUNT = 10


class FileSink(AuditSink):
    """Append audit events to a JSONL file with size-based rotation.

    Args:
        config: Common sink configuration.
        output_dir: Directory for the output file. Created if missing.
        file_name: Name of the JSONL file.
        max_bytes: Rotate when file exceeds this size.
        rotate_count: Number of rotated backups to keep.
    """

    def __init__(
        self,
        config: SinkConfig | None = None,
        output_dir: Path | str | None = None,
        file_name: str = _DEFAULT_FILE_NAME,
        max_bytes: int = _DEFAULT_MAX_BYTES,
        rotate_count: int = _DEFAULT_ROTATE_COUNT,
    ) -> None:
        super().__init__(config)
        self._output_dir = Path(output_dir) if output_dir else _DEFAULT_FILE_DIR
        self._file_name = file_name
        self._max_bytes = max_bytes
        self._rotate_count = rotate_count
        self._file_path = self._output_dir / self._file_name
        self._lock = threading.Lock()
        self._fh: typing.TextIO | None = None

    # ── Lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        """Ensure output directory exists."""
        super().start()
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def stop(self) -> None:
        """Flush and close file handle."""
        self.flush()
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None

    def flush(self) -> None:
        """Flush cached file handle."""
        if self._fh is not None:
            try:
                self._fh.flush()
            except OSError:
                pass

    # ── Core ─────────────────────────────────────────────────────────────

    def send(self, event: AuditEvent) -> None:
        """Write a single audit event as a JSON line."""
        try:
            line = event.to_json_line()
            with self._lock:
                self._write_line(line)
            self._record_success()
        except Exception as exc:
            logger.error("FileSink write failed: %s", exc)
            self._record_failure(str(exc))

    # ── Properties ──────────────────────────────────────────────────────

    @property
    def file_path(self) -> Path:
        """Path to the current output file."""
        return self._file_path

    # ── Internal ─────────────────────────────────────────────────────────

    def _write_line(self, line: str) -> None:
        """Append a line to the file, rotating if needed.

        Caches the file handle to avoid opening on every write.
        The handle is opened in append mode and flushed after each write.
        """
        if self._file_path.exists() and self._file_path.stat().st_size >= self._max_bytes:
            self._rotate()

        if self._fh is None:
            self._fh = open(self._file_path, "a", encoding="utf-8")
        self._fh.write(line + "\n")
        self._fh.flush()

    def _rotate(self) -> None:
        """Rotate: compress current file to .1.jsonl.gz, shift older files."""
        # Shift existing rotated files
        for i in range(self._rotate_count - 1, 0, -1):
            src = self._file_path.with_suffix(f".{i}.jsonl.gz")
            dst = self._file_path.with_suffix(f".{i + 1}.jsonl.gz")
            if src.exists():
                shutil.move(str(src), str(dst))

        # Compress current log to .1
        one_path = self._file_path.with_suffix(".1.jsonl.gz")
        with open(self._file_path, "rb") as f_in, gzip.open(one_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

        # Truncate current log
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None
        self._file_path.write_text("", encoding="utf-8")
