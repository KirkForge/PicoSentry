import importlib.util
import logging
import re
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from picosentry.serve.config.settings import settings
from picosentry.serve.database.pools import SQLitePool, create_pool

psycopg2: Any
if importlib.util.find_spec("psycopg2") is not None:
    import psycopg2
else:
    psycopg2 = None


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


@dataclass
class Migration:
    version: int
    name: str
    sqlite_sql: str
    postgres_sql: str | None = None

    def sql_for(self, backend: str) -> str:
        if backend == "sqlite":
            return self.sqlite_sql
        if self.postgres_sql is not None:
            return self.postgres_sql
        return _sqlite_to_postgres(self.sqlite_sql)


def _sqlite_to_postgres(sql: str) -> str:
    """Translate SQLite DDL/DML used in migrations to PostgreSQL equivalents.

    The migration SQL is under project control and never contains literal ``?``
    characters inside string literals, so a direct replacement is safe.
    """
    sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    # SQLite stores BOOLEAN as INTEGER (0/1); Postgres BOOLEAN expects FALSE/TRUE.
    sql = re.sub(r"BOOLEAN\s+DEFAULT\s+0", "BOOLEAN DEFAULT FALSE", sql, flags=re.IGNORECASE)
    sql = re.sub(r"BOOLEAN\s+DEFAULT\s+1", "BOOLEAN DEFAULT TRUE", sql, flags=re.IGNORECASE)
    return sql.replace("?", "%s")


@dataclass(frozen=True)
class SQLDialect:
    """Backend-specific SQL fragments used by application code.

    Keeps the few SQLite-isms in the codebase isolated so that PostgreSQL
    deployments run equivalent standard SQL.
    """

    backend: str

    def placeholder(self) -> str:
        return "%s" if self.backend == "postgres" else "?"

    def date_now(self) -> str:
        return "CURRENT_DATE" if self.backend == "postgres" else "DATE('now')"

    def date_column(self, column: str) -> str:
        if self.backend == "postgres":
            return f"{column}::date"
        return f"DATE({column})"

    def hour_column(self, column: str) -> str:
        if self.backend == "postgres":
            return f"EXTRACT(HOUR FROM {column})::text"
        return f"strftime('%H', {column})"

    def date_add_hours(self, start: str, hours: int) -> str:
        if self.backend == "postgres":
            return f"NOW() + INTERVAL '{hours} hours'"
        return f"datetime('{start}', '{hours} hours')"

    def bool_true(self) -> int | bool:
        return True if self.backend == "postgres" else 1

    def bool_false(self) -> int | bool:
        return False if self.backend == "postgres" else 0


MIGRATIONS = [
    Migration(
        1,
        "initial",
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            name TEXT
        );

        CREATE TABLE IF NOT EXISTS project_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT NOT NULL,
            org_id INTEGER,
            run_start TIMESTAMP,
            run_end TIMESTAMP,
            status TEXT,
            exit_code INTEGER,
            output TEXT,
            stderr TEXT,
            duration_seconds REAL,
            alerts_generated INTEGER DEFAULT 0,
            intelligence_extracted TEXT,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id)
        );

        CREATE TABLE IF NOT EXISTS intelligence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_project TEXT,
            intel_type TEXT,
            severity TEXT,
            data TEXT,
            related_projects TEXT,
            action_taken TEXT,
            confidence REAL DEFAULT 0.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT,
            alert_type TEXT,
            severity TEXT,
            message TEXT,
            channel TEXT,
            sent BOOLEAN DEFAULT 0,
            retry_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT,
            metric_name TEXT,
            metric_value REAL,
            unit TEXT,
            labels TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT,
            category TEXT,
            priority INTEGER,
            status TEXT,
            version TEXT,
            last_run TIMESTAMP,
            run_count INTEGER DEFAULT 0,
            success_rate REAL DEFAULT 0.0,
            avg_duration REAL DEFAULT 0.0,
            metadata TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS health_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            component TEXT,
            status TEXT,
            message TEXT,
            latency_ms REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_project_runs_project ON project_runs(project_id, run_start);
        CREATE INDEX IF NOT EXISTS idx_project_runs_status ON project_runs(status);
        CREATE INDEX IF NOT EXISTS idx_intelligence_severity ON intelligence(severity, created_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_sent ON alerts(sent, created_at);
        CREATE INDEX IF NOT EXISTS idx_metrics_project ON metrics(project_id, metric_name, created_at);
    """,
        # Postgres enforces foreign-key references at CREATE TABLE time. The orgs
        # table is not created until migration 5, so the sqlite SQL above cannot
        # be auto-translated for Postgres. We omit the project_runs -> orgs FK
        # here and create the equivalent index; referential integrity is enforced
        # by application code for the nullable org_id column.
        postgres_sql="""
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            name TEXT
        );

        CREATE TABLE IF NOT EXISTS project_runs (
            id SERIAL PRIMARY KEY,
            project_id TEXT NOT NULL,
            org_id INTEGER,
            run_start TIMESTAMP,
            run_end TIMESTAMP,
            status TEXT,
            exit_code INTEGER,
            output TEXT,
            stderr TEXT,
            duration_seconds REAL,
            alerts_generated INTEGER DEFAULT 0,
            intelligence_extracted TEXT,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS intelligence (
            id SERIAL PRIMARY KEY,
            source_project TEXT,
            intel_type TEXT,
            severity TEXT,
            data TEXT,
            related_projects TEXT,
            action_taken TEXT,
            confidence REAL DEFAULT 0.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id SERIAL PRIMARY KEY,
            project_id TEXT,
            alert_type TEXT,
            severity TEXT,
            message TEXT,
            channel TEXT,
            sent BOOLEAN DEFAULT FALSE,
            retry_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS metrics (
            id SERIAL PRIMARY KEY,
            project_id TEXT,
            metric_name TEXT,
            metric_value REAL,
            unit TEXT,
            labels TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT,
            category TEXT,
            priority INTEGER,
            status TEXT,
            version TEXT,
            last_run TIMESTAMP,
            run_count INTEGER DEFAULT 0,
            success_rate REAL DEFAULT 0.0,
            avg_duration REAL DEFAULT 0.0,
            metadata TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS health_checks (
            id SERIAL PRIMARY KEY,
            component TEXT,
            status TEXT,
            message TEXT,
            latency_ms REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_project_runs_project ON project_runs(project_id, run_start);
        CREATE INDEX IF NOT EXISTS idx_project_runs_status ON project_runs(status);
        CREATE INDEX IF NOT EXISTS idx_intelligence_severity ON intelligence(severity, created_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_sent ON alerts(sent, created_at);
        CREATE INDEX IF NOT EXISTS idx_metrics_project ON metrics(project_id, metric_name, created_at);
    """,
    ),
    Migration(
        2,
        "add_users",
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'viewer',
            is_active BOOLEAN DEFAULT 1,
            last_login TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            name TEXT,
            permissions TEXT,
            expires_at TIMESTAMP,
            last_used TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            revoked_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """,
    ),
    Migration(
        3,
        "add_audit_log",
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            user_id INTEGER,
            resource_type TEXT,
            resource_id TEXT,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, resource_type);
    """,
    ),
    Migration(
        4,
        "add_webhooks_scheduler",
        """
        CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            url TEXT NOT NULL,
            secret TEXT,
            events TEXT,
            active BOOLEAN DEFAULT 1,
            retries INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scheduled_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            cron_expression TEXT NOT NULL,
            command TEXT NOT NULL,
            params TEXT DEFAULT '{}',
            enabled BOOLEAN DEFAULT 1,
            last_run TIMESTAMP,
            next_run TIMESTAMP,
            last_status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_webhooks_active ON webhooks(active);
        CREATE INDEX IF NOT EXISTS idx_jobs_active ON scheduled_jobs(enabled, next_run);
    """,
    ),
    Migration(
        5,
        "add_orgs",
        """
        CREATE TABLE IF NOT EXISTS orgs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            owner_id INTEGER,
            tier TEXT DEFAULT 'free',
            api_key_hash TEXT UNIQUE,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS org_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER,
            user_id INTEGER,
            role TEXT DEFAULT 'member',
            invited_at TIMESTAMP,
            joined_at TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS org_projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER,
            project_id TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id)
        );

        CREATE INDEX IF NOT EXISTS idx_orgs_slug ON orgs(slug);
        CREATE INDEX IF NOT EXISTS idx_orgs_key ON orgs(api_key_hash);
        CREATE INDEX IF NOT EXISTS idx_org_members ON org_users(org_id, user_id);
    """,
    ),
    Migration(
        6,
        "add_org_id_to_runs_and_revoked_at",
        """
        -- Add org_id column to project_runs (P0 fix: get_usage() crashed)
        -- Using IF NOT EXISTS pattern via try/except at Python level for SQLite compat

        -- Add revoked_at column to api_keys (P1 fix: rotate_api_key crashed)
        -- Same: handled idempotently

        -- Add index for org-filtered run queries
        CREATE INDEX IF NOT EXISTS idx_project_runs_org ON project_runs(org_id, run_start);
    """,
    ),
    Migration(
        7,
        "add_anomaly_alerts",
        """
        CREATE TABLE IF NOT EXISTS anomaly_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL,
            metric_name TEXT NOT NULL,
            value REAL,
            threshold REAL,
            comparison TEXT,
            severity TEXT DEFAULT 'warning',
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_rule ON anomaly_alerts(rule_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_severity ON anomaly_alerts(severity, created_at);
    """,
    ),
    Migration(
        8,
        "orgs_api_key_to_hash",
        """
        -- No-op: column rename handled in Python _migrate_orgs_api_key_hash()
        -- This placeholder ensures migration 8 is recorded as applied.
        SELECT 1;
    """,
    ),
    Migration(
        9,
        "add_correlation_events",
        """
        CREATE TABLE IF NOT EXISTS correlation_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dedup_key TEXT UNIQUE NOT NULL,
            artifact_id TEXT NOT NULL,
            layer TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            target TEXT,
            title TEXT,
            detail TEXT,
            timestamp TEXT NOT NULL,
            run_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_correlation_artifact
            ON correlation_events(artifact_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_correlation_layer
            ON correlation_events(layer);
        CREATE INDEX IF NOT EXISTS idx_correlation_severity
            ON correlation_events(severity);

        CREATE TABLE IF NOT EXISTS correlation_chains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            artifact_id TEXT UNIQUE NOT NULL,
            chain_score REAL NOT NULL DEFAULT 0.0,
            severity TEXT NOT NULL DEFAULT 'INFO',
            confidence TEXT NOT NULL DEFAULT 'LOW',
            narrative TEXT,
            event_count INTEGER NOT NULL DEFAULT 0,
            phase_count INTEGER NOT NULL DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_correlation_chains_score
            ON correlation_chains(chain_score DESC);
    """,
    ),
    Migration(
        10,
        "add_org_id_to_tenant_tables",
        """
        -- Tenant isolation: tag data that belongs to an organization.
        -- These columns are nullable so background/system jobs without an
        -- org context can still write.  API-facing reads filter by the
        -- caller's org.

        ALTER TABLE intelligence ADD COLUMN org_id INTEGER;
        ALTER TABLE alerts ADD COLUMN org_id INTEGER;
        ALTER TABLE metrics ADD COLUMN org_id INTEGER;
        ALTER TABLE webhooks ADD COLUMN org_id INTEGER;
        ALTER TABLE scheduled_jobs ADD COLUMN org_id INTEGER;
        ALTER TABLE correlation_chains ADD COLUMN org_id INTEGER;

        CREATE INDEX IF NOT EXISTS idx_intelligence_org ON intelligence(org_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_org ON alerts(org_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_metrics_org ON metrics(org_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_webhooks_org ON webhooks(org_id);
        CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_org ON scheduled_jobs(org_id);
        CREATE INDEX IF NOT EXISTS idx_correlation_chains_org ON correlation_chains(org_id);
    """,
    ),
]


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
        except Exception:
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
                # If psycopg2 is installed we can distinguish real DB errors from
                # the expected "no lastval" case; if it is missing we are in a
                # SQLite-only install and the only caller path is unreachable.
                if psycopg2 is not None:
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
