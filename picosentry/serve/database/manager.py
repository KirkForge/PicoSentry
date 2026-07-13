from __future__ import annotations

import logging
import sqlite3
import sys
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from picosentry.serve.config.settings import settings
from picosentry.serve.database._schema import MIGRATIONS, SQLDialect
from picosentry.serve.database.pools import SQLitePool, create_pool

try:
    import psycopg2
except ImportError:
    psycopg2 = cast("Any", None)


def _adapt_datetime(dt):
    return dt.isoformat()


def _convert_timestamp(val):
    if isinstance(val, bytes):
        val = val.decode()
    if val:
        return datetime.fromisoformat(val)
    return None


sqlite3.register_adapter(datetime, _adapt_datetime)
sqlite3.register_converter("TIMESTAMP", _convert_timestamp)

logger = logging.getLogger("picoshogun.DB")


class ConnectionPool:
    def acquire(self):
        raise NotImplementedError

    def release(self, conn):
        raise NotImplementedError

    def close_all(self):
        raise NotImplementedError


class DatabaseManager:
    def __init__(self, db_path: Path | None = None, backend: str | None = None):
        self._backend = backend or settings.database.backend
        self._pool = create_pool(backend=self._backend, db_path=db_path)
        self._lock = self._pool.lock() if isinstance(self._pool, SQLitePool) else threading.Lock()
        self._init_migrations()

    @property
    def db_path(self) -> Path:
        if isinstance(self._pool, SQLitePool):
            return self._pool.db_path
        return Path()

    @property
    def backend(self) -> str:
        return self._backend

    @property
    def dialect(self) -> SQLDialect:
        return SQLDialect(self._backend)

    def _prepare_sql(self, sql: str) -> str:
        """Translate SQLite-isms in runtime SQL for the active backend."""
        if self._backend != "postgres":
            return sql
        # Migration SQL is backend-specific; runtime SQL uses ? placeholders.
        # The codebase never puts a literal ? inside SQL string literals.
        return sql.replace("?", "%s")

    def _get_connection(self):
        return self._pool.acquire()

    @contextmanager
    def transaction(self):
        conn = self._get_connection()
        try:
            if isinstance(self._pool, SQLitePool):
                conn.execute("BEGIN")
            # Postgres connections have autocommit=False, so transactions
            # are implicit — no explicit BEGIN needed.
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise

    def _cursor(self, conn, sql: str, params: tuple = ()):
        """Execute SQL and return cursor, handling backend differences.
        SQLite: conn.execute() returns cursor directly.
        Postgres: needs cursor = conn.cursor(); cursor.execute().
        """
        sql = self._prepare_sql(sql)
        if isinstance(self._pool, SQLitePool):
            return conn.execute(sql, params)
        cursor = conn.cursor()
        cursor.execute(sql, params)
        return cursor

    def _row_to_dict(self, row, cursor) -> dict:
        """Convert a fetched row to dict, handling backend differences.
        SQLite Row objects are already dict-like.  Postgres returns tuples.
        """
        if isinstance(self._pool, SQLitePool):
            return dict(row)
        cols = [desc[0] for desc in cursor.description] if cursor.description else []
        return dict(zip(cols, row, strict=False))

    def execute(self, sql: str, params: tuple = ()) -> list:
        with self._lock:
            conn = self._get_connection()
            cursor = self._cursor(conn, sql, params)
            # DDL and DML statements do not return a result set. SQLite tolerates
            # fetchall() in that case, but psycopg2 raises ProgrammingError, so
            # we guard on cursor.description before fetching.
            if cursor.description is None:
                return []
            rows = cursor.fetchall()
            return [self._row_to_dict(r, cursor) for r in rows]

    def execute_one(self, sql: str, params: tuple = ()) -> dict | None:
        results = self.execute(sql, params)
        return results[0] if results else None

    def execute_insert(self, sql: str, params: tuple = ()) -> int:
        with self._lock:
            conn = self._get_connection()
            cursor = self._cursor(conn, sql, params)
            conn.commit()
            if isinstance(self._pool, SQLitePool):
                return cursor.lastrowid
            # Postgres: ask for the last sequence value assigned in this
            # session. Tables without a serial column will raise; we return 0.
            try:
                cursor.execute("SELECT lastval()")
                return cursor.fetchone()[0]
            except Exception:
                # lastval() can fail for tables without a serial column or when
                # psycopg2 exposes OperationalError/ProgrammingError. We want to
                # return 0 for the expected "no lastval" case, but re-raise
                # truly unexpected programmer errors. Because the installed
                # exception types vary by extras, we check whether the raised
                # exception is a psycopg2 error before deciding to swallow it.
                if psycopg2 is not None and isinstance(sys.exc_info()[1], psycopg2.Error):
                    logger.debug("lastval() not available for this table; returning 0")
                    return 0
                raise

    def _migrate_orgs_api_key_hash(self):

        try:
            if self._backend == "postgres":
                cols = self.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = 'orgs' AND table_schema = 'public'"
                )
                col_names = [row["column_name"] for row in cols]
            else:
                cols = self.execute("PRAGMA table_info(orgs)")
                if not cols:
                    return  # Table doesn't exist yet
                col_names = [row["name"] for row in cols]
            if "api_key" in col_names and "api_key_hash" not in col_names:
                self.execute("ALTER TABLE orgs RENAME COLUMN api_key TO api_key_hash")
                logger.info("Renamed orgs.api_key → orgs.api_key_hash")
            elif "api_key" in col_names and "api_key_hash" in col_names:
                logger.warning("Both api_key and api_key_hash exist in orgs — skipping rename")
        except (OSError, ValueError) as e:
            logger.debug("orgs migration check skipped: %s", e)

    def _init_migrations(self):
        self.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                name TEXT
            )
        """)

        current_version = self.execute_one("SELECT MAX(version) as v FROM schema_version")
        current = current_version["v"] if current_version and current_version["v"] is not None else 0

        for migration in MIGRATIONS:
            if migration.version > current:
                logger.info("Applying migration %s: %s", migration.version, migration.name)
                sql = migration.sql_for(self._backend)
                for raw_stmt in sql.split(";"):
                    stmt = raw_stmt.strip()
                    if stmt:
                        try:
                            self.execute(stmt + ";")
                        except (OSError, ValueError) as e:
                            err_str = str(e).lower()
                            if "duplicate column" in err_str or "already exists" in err_str:
                                logger.debug("Migration idempotent skip: %s", e)
                            else:
                                raise
                # schema_version has a simple integer primary key; use execute()
                # to avoid needing a generated id on either backend.
                self.execute(
                    "INSERT INTO schema_version (version, name) VALUES (?, ?)", (migration.version, migration.name)
                )
                logger.info("Migration %s applied", migration.version)

        self._migrate_orgs_api_key_hash()

    def backup(self) -> Path:
        backup_dir = settings.database.backup_dir
        backup_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"picoshogun_{timestamp}.db"

        if isinstance(self._pool, SQLitePool):
            self._pool.backup(backup_path)
            logger.info("Database backed up to %s", backup_path)
        else:
            logger.warning("Backup is only supported for SQLite backend. Use pg_dump for Postgres.")
        return backup_path

    def close(self):
        self._pool.close_all()


db = DatabaseManager()
