import gzip
import logging
import shutil
import threading
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger("picoshogun.LogManager")


class LogManager:
    def __init__(
        self, log_dir: str | None = None, max_size_mb: int = 100, max_files: int = 10, retention_days: int = 30
    ):
        self.log_dir = Path(log_dir) if log_dir else Path(__file__).parent.parent / "logs"
        self.max_size = max_size_mb * 1024 * 1024
        self.max_files = max_files
        self.retention_days = retention_days
        self._lock = threading.Lock()
        self._ensure_dir()

    def _ensure_dir(self):
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def rotate(self, log_file: str | None = None) -> str | None:
        if log_file:
            target = Path(log_file)
        else:
            logs = self._get_log_files()
            if not logs:
                return None
            target = max(logs, key=lambda p: p.stat().st_size)

        if not target.exists():
            return None

        with self._lock:
            size = target.stat().st_size
            if size < self.max_size:
                return None

            self._rotate_files(target)

            self._compress_old(target)

            logger.info("Rotated: %s (%s bytes)", target.name, size)
            return str(target)

    def _rotate_files(self, target: Path):

        oldest = Path(f"{target}.{self.max_files}.gz")
        if oldest.exists():
            oldest.unlink()

        for i in range(self.max_files - 1, 0, -1):
            old = Path(f"{target}.{i}.gz")
            new = Path(f"{target}.{i + 1}.gz")
            if old.exists():
                shutil.move(str(old), str(new))

        first = Path(f"{target}.1")
        if target.exists():
            shutil.move(str(target), str(first))

    def _compress_old(self, target: Path):
        first = Path(f"{target}.1")
        if first.exists():
            gz_path = Path(f"{target}.1.gz")
            with first.open("rb") as f_in, gzip.open(gz_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            first.unlink()

    def cleanup(self) -> int:
        if self.retention_days <= 0:
            return 0

        cutoff = datetime.now() - timedelta(days=self.retention_days)
        removed = 0

        for log_file in self._get_log_files():
            if log_file.suffix == ".gz":
                mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                if mtime < cutoff:
                    log_file.unlink()
                    removed += 1

        if removed > 0:
            logger.info("Cleaned up %s old log files", removed)

        return removed

    def _get_log_files(self) -> list[Path]:
        if not self.log_dir.exists():
            return []
        return [p for p in self.log_dir.iterdir() if p.suffix in (".log", ".gz")]

    def get_stats(self) -> dict:
        files = self._get_log_files()
        total_size = sum(f.stat().st_size for f in files)

        return {
            "directory": str(self.log_dir),
            "file_count": len(files),
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "max_size_mb": self.max_size / (1024 * 1024),
            "retention_days": self.retention_days,
            "files": [
                {
                    "name": f.name,
                    "size": f.stat().st_size,
                    "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                }
                for f in sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)
            ],
        }

    def query(
        self, level: str | None = None, source: str | None = None, search: str | None = None, limit: int = 100
    ) -> list[dict]:
        import re

        entries = []
        level_pattern = re.compile(rf"^{level}", re.IGNORECASE) if level else None

        for log_file in self._get_log_files():
            if log_file.suffix != ".log":
                continue
            try:
                with log_file.open() as f:
                    for raw_line in f:
                        line = raw_line.strip()
                        if not line:
                            continue
                        if level_pattern and not level_pattern.search(line):
                            continue
                        if source and source.lower() not in line.lower():
                            continue
                        if search and search.lower() not in line.lower():
                            continue
                        entries.append({"file": log_file.name, "line": line})
                        if len(entries) >= limit:
                            return entries
            except (OSError, UnicodeDecodeError):
                logger.warning("Failed to read log file %s", log_file, exc_info=True)
                continue
        return entries

    def auto_rotate(self) -> None:
        for log_file in self._get_log_files():
            if log_file.suffix == ".log":
                self.rotate(str(log_file))
        self.cleanup()


log_manager = LogManager()
