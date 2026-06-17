import logging
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

from picosentry.serve.config.settings import settings

logger = logging.getLogger("picoshogun.DB.Pool")


class SQLitePool:

    param_style = "qmark"  # SQLite uses ? for parameters

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or settings.database.path
        self._local = threading.local()
        self._lock = threading.Lock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def acquire(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self.db_path),
                timeout=settings.database.timeout,
                check_same_thread=False,
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            )
            journal = settings.database.journal_mode.upper()
            sync_level = settings.database.synchronous.upper()
            self._local.conn.execute(f"PRAGMA journal_mode={journal}")
            self._local.conn.execute(f"PRAGMA synchronous={sync_level}")
            if journal == "WAL":
                threshold = settings.database.wal_checkpoint_threshold
                self._local.conn.execute(f"PRAGMA wal_autocheckpoint={threshold}")
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def release(self, conn: sqlite3.Connection) -> None:
        pass

    def close_all(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    @contextmanager
    def transaction(self):
        conn = self.acquire()
        try:
            conn.execute("BEGIN")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def lock(self) -> threading.Lock:
        return self._lock

    def backup(self, dest_path: Path) -> None:
        with self._lock:
            source = sqlite3.connect(str(self.db_path))
            dest = sqlite3.connect(str(dest_path))
            source.backup(dest)
            dest.close()
            source.close()


class PostgresPool:

    param_style = "format"  # Postgres uses %s for parameters

    def __init__(self, url: str | None = None):
        self._url = url or settings.database.url or "postgresql://localhost:5432/picoshogun"
        self._local = threading.local()
        self._lock = threading.Lock()
        self._psycopg2 = None

    def _ensure_psycopg2(self):
        if self._psycopg2 is not None:
            return
        try:
            import psycopg2 as pg
            import psycopg2.extras
            self._psycopg2 = pg
            self._extras = psycopg2.extras
        except ImportError as err:
            raise ImportError(
                "Postgres backend requires psycopg2. Install with: "
                "pip install psycopg2-binary\n"
                "Or switch to SQLite: export PICOSHOGUN_DATABASE_BACKEND=sqlite"
            ) from err

    def acquire(self):
        self._ensure_psycopg2()
        if not hasattr(self._local, "conn") or self._local.conn is None or self._local.conn.closed:
            self._local.conn = self._psycopg2.connect(self._url)
            self._local.conn.autocommit = False
        return self._local.conn

    def release(self, conn) -> None:
        pass  # Per-thread connection; closed in close_all()

    def close_all(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn and not self._local.conn.closed:
            self._local.conn.close()
            self._local.conn = None

    def lock(self) -> threading.Lock:
        return self._lock

    def backup(self, dest_path: Path) -> None:
        logger.warning(
            "Backup is not supported for Postgres backend. Use pg_dump manually."
        )


def create_pool(backend: str | None = None, db_path: Path | None = None, url: str | None = None):
    effective_backend = backend or settings.database.backend
    if effective_backend == "postgres":
        return PostgresPool(url=url)
    return SQLitePool(db_path=db_path)
