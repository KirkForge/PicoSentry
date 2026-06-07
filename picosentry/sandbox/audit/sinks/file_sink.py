
from __future__ import annotations

import gzip
import logging
import shutil
import threading
import typing
from pathlib import Path

from picosentry.sandbox.audit.logger import AuditEvent
from picosentry.sandbox.audit.sinks.base import AuditSink, SinkConfig

logger = logging.getLogger("picodome.audit.sink.file")


_DEFAULT_FILE_DIR = Path.home() / ".picodome" / "sink"
_DEFAULT_FILE_NAME = "audit_sink.jsonl"
_DEFAULT_MAX_BYTES = 50 * 1024 * 1024  # 50 MiB
_DEFAULT_ROTATE_COUNT = 10


class FileSink(AuditSink):

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


    def start(self) -> None:
        super().start()
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def stop(self) -> None:
        self.flush()
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None

    def flush(self) -> None:
        if self._fh is not None:
            try:
                self._fh.flush()
            except OSError:
                pass


    def send(self, event: AuditEvent) -> None:
        try:
            line = event.to_json_line()
            with self._lock:
                self._write_line(line)
            self._record_success()
        except Exception as exc:
            logger.error("FileSink write failed: %s", exc)
            self._record_failure(str(exc))


    @property
    def file_path(self) -> Path:
        return self._file_path


    def _write_line(self, line: str) -> None:
        if self._file_path.exists() and self._file_path.stat().st_size >= self._max_bytes:
            self._rotate()

        if self._fh is None:


            self._fh = open(self._file_path, "a", encoding="utf-8")  # noqa: SIM115
        self._fh.write(line + "\n")
        self._fh.flush()

    def _rotate(self) -> None:

        for i in range(self._rotate_count - 1, 0, -1):
            src = self._file_path.with_suffix(f".{i}.jsonl.gz")
            dst = self._file_path.with_suffix(f".{i + 1}.jsonl.gz")
            if src.exists():
                shutil.move(str(src), str(dst))


        one_path = self._file_path.with_suffix(".1.jsonl.gz")
        with open(self._file_path, "rb") as f_in, gzip.open(one_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)


        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None
        self._file_path.write_text("", encoding="utf-8")
