"""Database connection pool implementations.

SQLitePool — thread-local connection pool for SQLite (default).
PostgresPool — stub for future psycopg/asyncpg migration.

The pool interface is defined in database.manager.ConnectionPool.
Switch backends via config: PICOSHOGUN_DATABASE_BACKEND=postgres.
"""
import logging
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

from picosentry.serve.config.settings import settings

logger = logging.getLogger("picoshogun.DB.Pool")


class SQLitePool:
    """Thread-local SQLite connection pool.

    Each thread gets its own connection, created on first use.
    WAL mode, synchronous, and auto-checkpoint are configured
    from ``settings.database``.

    This replaces the previous inline connection logic in DatabaseManager.
    """

    param_style = "qmark"  # SQLite uses ? for parameters

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or settings.database.path
        self._local = threading.local()
        self._lock = threading.Lock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def acquire(self) -> sqlite3.Connection:
        """Get a thread-local SQLite connection."""
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
        """No-op for SQLite — thread-local connections are reused."""
        pass

    def close_all(self) -> None:
        """Close the current thread's connection."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    @contextmanager
    def transaction(self):
        """Context manager for database transactions."""
        conn = self.acquire()
        try:
            conn.execute("BEGIN")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def lock(self) -> threading.Lock:
        """Return the thread-safety lock for write operations."""
        return self._lock

    def backup(self, dest_path: Path) -> None:
        """Create a backup of the SQLite database to dest_path."""
        with self._lock:
            source = sqlite3.connect(str(self.db_path))
            dest = sqlite3.connect(str(dest_path))
            source.backup(dest)
            dest.close()
            source.close()


class PostgresPool:
    """PostgreSQL connection pool (stub for migration path).

    To complete the Postgres migration:
    1. Install psycopg (v3): ``pip install psycopg[binary]``
    2. Set ``PICOSHOGUN_DATABASE_BACKEND=postgres``
    3. Set ``PICOSHOGUN_DATABASE_URL=PICOSHOGUN_DATABASE_URL=<your-postgres-url>``
    4. Implement the acquire/release/close_all methods below.
    5. Adjust SQL in migrations and queries:
       - Replace ``?`` params with ``%s``
       - Replace ``AUTOINCREMENT`` with ``SERIAL`` or ``GENERATED ALWAYS AS IDENTITY``
       - Replace ``strftime`` with ``TO_CHAR`` / ``EXTRACT``
       - Replace ``julianday`` with Postgres date math
       - Replace ``datetime('now', ...)`` with ``NOW() - INTERVAL '...'``
    """

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
    """Factory: create the appropriate connection pool based on config.

    Args:
        backend: Override backend ('sqlite' or 'postgres'). If None, reads
                 from PICOSHOGUN_DATABASE_BACKEND env var (default: 'sqlite').
        db_path: SQLite database path (for SQLite backend only).
        url: Postgres connection URL (for Postgres backend only).

    Returns:
        SQLitePool or PostgresPool instance.
    """
    effective_backend = backend or settings.database.backend
    if effective_backend == "postgres":
        return PostgresPool(url=url)
    return SQLitePool(db_path=db_path)
