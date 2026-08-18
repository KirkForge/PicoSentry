from __future__ import annotations

import contextlib
import logging
import re
import sqlite3
import sys
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar, cast

from picosentry.serve.config.settings import settings
from picosentry.serve.database._schema import (  # noqa: F401
    MIGRATIONS,
    SQLDialect,
    Migration,
)
from picosentry.serve.database.pools import ReadWriteLock, SQLitePool, create_pool

try:
    import psycopg2
except ImportError:
    psycopg2 = cast("Any", None)


def _adapt_datetime(dt):
    return dt.isoformat()


# Boolean columns per _schema.py DDL — compared to 1/0 literals in runtime
# SQL (portable on SQLite, rejected by postgres BOOLEAN columns).
_BOOL_LITERAL_RE = re.compile(r"\b(is_active|active|sent|enabled)(\s*[=!<>]+\s*)([01])\b")


def _convert_timestamp(val):
    if isinstance(val, bytes):
        val = val.decode()
    if val:
        return datetime.fromisoformat(val)
    return None


sqlite3.register_adapter(datetime, _adapt_datetime)
sqlite3.register_converter("TIMESTAMP", _convert_timestamp)

logger = logging.getLogger("picoshogun.DB")


class DatabaseManager:
    # Statements that only read take the RW lock's shared half; anything
    # else (or anything unrecognized, e.g. WITH ... INSERT) takes the
    # exclusive half — failing closed toward serialization, never toward
    # concurrent writes.
    _READ_PREFIXES: ClassVar[tuple[str, ...]] = ("SELECT", "PRAGMA", "EXPLAIN")

    def __init__(self, db_path: Path | None = None, backend: str | None = None):
        self._backend = backend or settings.database.backend
        self._pool = create_pool(backend=self._backend, db_path=db_path)
        # The manager owns the statement lock: reads share it, writes take
        # it exclusively, and backup/restore hold the write half across
        # file swaps. Per-thread connections make concurrent reads safe.
        self._lock = ReadWriteLock()
        # Per-thread transaction() depth: execute() must not commit/rollback
        # a transaction opened by an enclosing transaction() on this thread.
        self._tx_depth = threading.local()
        self._init_migrations()

    def _statement_lock(self, sql: str):
        """Shared read lock for read-only statements, exclusive for writes."""
        return self._lock.read() if sql.lstrip().upper().startswith(self._READ_PREFIXES) else self._lock.write()

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

    def _validate_param_count(self, sql: str, params: tuple) -> None:
        # Runs on the raw SQL before _prepare_sql() translates ? -> %s for
        # postgres. Both ? (codebase convention) and %s (postgres-native
        # callers) end up as %s in the final SQL, so count both.
        expected = sql.count("?") + sql.count("%s")
        if expected != len(params):
            raise ValueError(
                f"Parameter count mismatch: SQL has {expected} placeholders but {len(params)} parameters were provided"
            )

    def _prepare_sql(self, sql: str) -> str:
        """Translate SQLite-isms in runtime SQL for the active backend."""
        if self._backend != "postgres":
            return sql
        # Migration SQL is backend-specific; runtime SQL uses ? placeholders.
        # The codebase never puts a literal ? inside SQL string literals.
        sql = sql.replace("?", "%s")
        # SQLite accepts `boolean_col = 1`; postgres BOOLEAN columns reject
        # integer literals ("operator does not exist: boolean = integer").
        # Translate 1/0 literals compared against the schema's boolean
        # columns (see _schema.py) to TRUE/FALSE. Integer columns are
        # untouched: only these four names are BOOLEAN in the DDL.
        sql = _BOOL_LITERAL_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{'TRUE' if m.group(3) == '1' else 'FALSE'}", sql)
        return sql

    def _get_connection(self):
        return self._pool.acquire()

    def _in_transaction(self) -> bool:
        return getattr(self._tx_depth, "depth", 0) > 0

    @contextmanager
    def transaction(self, immediate: bool = True):
        conn = self._get_connection()
        depth = getattr(self._tx_depth, "depth", 0) + 1
        self._tx_depth.depth = depth
        try:
            if isinstance(self._pool, SQLitePool):
                # BEGIN IMMEDIATE takes the write lock up front, so concurrent
                # writers serialize at the DB instead of racing between a read
                # and their INSERT (audit hash chain depends on this). It is
                # also the DEFAULT because every deferred caller is a
                # read-check-then-write pattern: cross-process, a deferred
                # BEGIN→read→write-upgrade deadlocks instantly ("database is
                # locked") whenever another worker wrote since the read began
                # — the WAL snapshot-upgrade failure sqlite will not retry.
                conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            # Postgres connections have autocommit=False, so transactions
            # are implicit — no explicit BEGIN needed.
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            self._tx_depth.depth = depth - 1

    def _cursor(self, conn, sql: str, params: tuple = ()):
        """Execute SQL and return cursor, handling backend differences.
        SQLite: conn.execute() returns cursor directly.
        Postgres: needs cursor = conn.cursor(); cursor.execute().
        """
        self._validate_param_count(sql, params)
        sql = self._prepare_sql(sql)
        if isinstance(self._pool, SQLitePool):
            return conn.execute(sql, params)
        cursor = conn.cursor()
        if params:
            cursor.execute(sql, params)
        else:
            # psycopg2 activates %-interpolation whenever a params argument is
            # present — even an empty tuple — so DDL containing a literal '%'
            # (migration CASE ... LIKE '%admin%') dies with IndexError.
            # With no parameters to bind, execute the SQL bare.
            cursor.execute(sql)
        return cursor

    def _row_to_dict(self, row, cursor) -> dict:
        """Convert a fetched row to dict, handling backend differences.
        SQLite Row objects are already dict-like.  Postgres returns tuples.
        """
        if isinstance(self._pool, SQLitePool):
            return dict(row)
        cols = [desc[0] for desc in cursor.description] if cursor.description else []
        return dict(zip(cols, row, strict=False))

    def _finish_pg_statement(self, conn, cursor_description) -> None:
        """End the implicit per-statement transaction on the postgres path.

        PostgresPool connections run autocommit=False, so without this every
        execute() left an idle-in-transaction session (snapshot/lock retention)
        and DML was lost on restart unless a later execute_insert() happened to
        commit the bleed-together transaction. Result-set statements (SELECT)
        are rolled back — releasing the snapshot is enough; DML/DDL (no result
        set) are committed so they are durable immediately. No-op on SQLite
        (isolation_level=None connections are always autocommit) and inside an
        explicit transaction() (the caller owns commit/rollback).
        """
        if isinstance(self._pool, SQLitePool) or self._in_transaction():
            return
        if cursor_description is None:
            conn.commit()
        else:
            conn.rollback()

    def execute(self, sql: str, params: tuple = ()) -> list:
        with self._statement_lock(sql):
            conn = self._get_connection()
            try:
                cursor = self._cursor(conn, sql, params)
            except BaseException:
                if not isinstance(self._pool, SQLitePool) and not self._in_transaction():
                    # Clear the aborted transaction so the pooled connection
                    # stays usable for the next statement.
                    with contextlib.suppress(Exception):
                        conn.rollback()
                raise
            self._finish_pg_statement(conn, cursor.description)
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

    def execute_on(self, conn, sql: str, params: tuple = ()) -> list:
        """Execute SQL on an explicit connection (inside transaction()).

        Handles backend cursor differences like execute(), but on a caller-
        supplied connection so read+write pairs stay in one transaction.
        """
        cursor = self._cursor(conn, sql, params)
        if cursor.description is None:
            return []
        return [self._row_to_dict(r, cursor) for r in cursor.fetchall()]

    def execute_insert(self, sql: str, params: tuple = ()) -> int:
        with self._lock.write():
            conn = self._get_connection()
            cursor = self._cursor(conn, sql, params)
            conn.commit()
            if isinstance(self._pool, SQLitePool):
                return cursor.lastrowid
            # Postgres: ask for the last sequence value assigned in this
            # session. Tables without a serial column will raise; we return 0.
            try:
                cursor.execute("SELECT lastval()")
                value = cursor.fetchone()[0]
            except Exception:
                # lastval() can fail for tables without a serial column or when
                # psycopg2 exposes OperationalError/ProgrammingError. We want to
                # return 0 for the expected "no lastval" case, but re-raise
                # truly unexpected programmer errors. Because the installed
                # exception types vary by extras, we check whether the raised
                # exception is a psycopg2 error before deciding to swallow it.
                if psycopg2 is not None and isinstance(sys.exc_info()[1], psycopg2.Error):
                    logger.debug("lastval() not available for this table; returning 0")
                    value = 0
                else:
                    raise
            finally:
                if not isinstance(self._pool, SQLitePool) and not self._in_transaction():
                    # The lastval() SELECT (or its failure) opened/aborted
                    # another implicit transaction; close it so the pooled
                    # connection is clean for the next statement.
                    with contextlib.suppress(Exception):
                        conn.rollback()
            return value

    def execute_update(self, sql: str, params: tuple = ()) -> int:
        """Execute a write statement and return the affected-row count.

        The lease acquire/release protocol is a single conditional UPDATE
        whose rowcount IS the answer (1 = won the lease, 0 = someone else
        holds it); execute() discards rowcount, so this sibling exists.
        """
        with self._lock.write():
            conn = self._get_connection()
            cursor = self._cursor(conn, sql, params)
            count = cursor.rowcount if cursor.rowcount is not None else 0
            if not isinstance(self._pool, SQLitePool) and not self._in_transaction():
                conn.commit()
            return count

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
                # One transaction per migration: a crash mid-migration no
                # longer leaves a half-applied schema, and BEGIN IMMEDIATE
                # serializes racing workers booting against a fresh DB at
                # the database itself. The ON CONFLICT DO NOTHING version
                # insert means the loser of that race converges instead of
                # dying on the schema_version primary key.
                with self.transaction(immediate=True) as conn:
                    for raw_stmt in sql.split(";"):
                        stmt = raw_stmt.strip()
                        if stmt:
                            try:
                                self.execute_on(conn, stmt + ";")
                            except (OSError, ValueError, sqlite3.OperationalError) as e:
                                err_str = str(e).lower()
                                if "duplicate column" in err_str or "already exists" in err_str:
                                    logger.debug("Migration idempotent skip: %s", e)
                                else:
                                    raise
                    # schema_version has a simple integer primary key; use
                    # execute_on() to avoid needing a generated id on either
                    # backend, staying inside the migration transaction.
                    self.execute_on(
                        conn,
                        "INSERT INTO schema_version (version, name) VALUES (?, ?) ON CONFLICT (version) DO NOTHING",
                        (migration.version, migration.name),
                    )
                logger.info("Migration %s applied", migration.version)

        self._migrate_orgs_api_key_hash()

    def backup(self) -> Path:
        backup_dir = settings.database.backup_dir
        backup_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"picoshogun_{timestamp}.db"

        if isinstance(self._pool, SQLitePool):
            # The write half excludes in-flight statements for the
            # sqlite3 backup() read of the live file.
            with self._lock.write():
                self._pool.backup(backup_path)
            logger.info("Database backed up to %s", backup_path)
        else:
            logger.warning("Backup is only supported for SQLite backend. Use pg_dump for Postgres.")
        return backup_path

    def close(self):
        self._pool.close_all()


db = DatabaseManager()
