import contextlib
import logging
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from picosentry.serve.config.settings import settings

logger = logging.getLogger("picoshogun.DB.Pool")


class SQLitePool:
    param_style = "qmark"  # SQLite uses ? for parameters

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or settings.database.path
        self._local = threading.local()
        self._lock = threading.Lock()
        # ponytail: _lock doubles as the manager's outer write lock (pool.lock()),
        # and acquire() runs inside it — the conn set needs its own lock.
        self._conns_lock = threading.Lock()
        self._all_conns: set[sqlite3.Connection] = set()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _discard(self, conn: sqlite3.Connection) -> None:
        with contextlib.suppress(Exception):
            conn.close()
        with self._conns_lock:
            self._all_conns.discard(conn)

    def acquire(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.execute("SELECT 1")
            except sqlite3.Error:
                self._discard(conn)
                conn = None
        if conn is None:
            self._local.conn = sqlite3.connect(
                str(self.db_path),
                timeout=settings.database.timeout,
                check_same_thread=False,
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
                isolation_level=None,
            )
            with self._conns_lock:
                self._all_conns.add(self._local.conn)
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
        with self._conns_lock:
            conns = self._all_conns
            self._all_conns = set()
            for conn in conns:
                with contextlib.suppress(Exception):
                    conn.close()
        if hasattr(self._local, "conn"):
            self._local.conn = None

    @contextmanager
    def transaction(self):
        conn = self.acquire()
        try:
            conn.execute("BEGIN")
            yield conn
            conn.commit()
        except BaseException:
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
        self._conns_lock = threading.Lock()
        self._all_conns: set[Any] = set()

    def _discard(self, conn: Any) -> None:
        with contextlib.suppress(Exception):
            conn.close()
        with self._conns_lock:
            self._all_conns.discard(conn)

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
        conn = getattr(self._local, "conn", None)
        if conn is not None and not conn.closed:
            try:
                conn.cursor().execute("SELECT 1")
            except self._psycopg2.Error:
                self._discard(conn)
                conn = None
        if conn is not None and conn.closed:
            self._discard(conn)
            conn = None
        if conn is None:
            conn = self._psycopg2.connect(self._url, connect_timeout=5)
            conn.autocommit = False
            self._local.conn = conn
            with self._conns_lock:
                self._all_conns.add(conn)
        return self._local.conn

    def release(self, conn) -> None:
        pass  # Per-thread connection; closed in close_all()

    def close_all(self) -> None:
        with self._conns_lock:
            conns = self._all_conns
            self._all_conns = set()
            for conn in conns:
                with contextlib.suppress(Exception):
                    conn.close()
        if hasattr(self._local, "conn"):
            self._local.conn = None

    def lock(self) -> threading.Lock:
        return self._lock

    def backup(self, dest_path: Path) -> None:
        logger.warning("Backup is not supported for Postgres backend. Use pg_dump manually.")


def create_pool(backend: str | None = None, db_path: Path | None = None, url: str | None = None):
    effective_backend = backend or settings.database.backend
    if effective_backend == "postgres":
        return PostgresPool(url=url)
    return SQLitePool(db_path=db_path)
