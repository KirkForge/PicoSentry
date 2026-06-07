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
        self._url = url or "postgresql://localhost:5432/picoshogun"
        logger.warning(
            "PostgresPool initialized but not yet implemented. "
            "Set PICOSHOGUN_DATABASE_BACKEND=sqlite to use the default backend. "
            "Postgres support requires psycopg or asyncpg. "
            "See database/pools.py for migration instructions."
        )

    def acquire(self):
        raise NotImplementedError(
            "PostgresPool.acquire() not implemented. "
            "Install psycopg and implement connection pooling, or use "
            "PICOSHOGUN_DATABASE_BACKEND=sqlite."
        )

    def release(self, conn):
        raise NotImplementedError(
            "PostgresPool.release() not implemented. "
            "Use PICOSHOGUN_DATABASE_BACKEND=sqlite."
        )

    def close_all(self):
        raise NotImplementedError(
            "PostgresPool.close_all() not implemented. "
            "Use PICOSHOGUN_DATABASE_BACKEND=sqlite."
        )


def create_pool(backend: str | None = None, db_path: Path | None = None, url: str | None = None):
    effective_backend = backend or settings.database.backend
    if effective_backend == "postgres":
        return PostgresPool(url=url)
    return SQLitePool(db_path=db_path)
