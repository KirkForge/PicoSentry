"""Database layer with migrations, connection pooling, and ORM-like interface."""
import logging
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from picosentry.serve.config.settings import settings
from picosentry.serve.database.pools import SQLitePool, create_pool


# ─── Python 3.12+ datetime adapter ─────────────────────────────────────
# Silence DeprecationWarning: default datetime adapter is deprecated
def _adapt_datetime(dt):
    """ISO 8601 adapter for Python 3.12+ sqlite3 datetime deprecation."""
    return dt.isoformat()


def _convert_timestamp(val):
    """Convert ISO 8601 timestamp string back to datetime."""
    if isinstance(val, bytes):
        val = val.decode()
    if val:
        return datetime.fromisoformat(val)
    return None


sqlite3.register_adapter(datetime, _adapt_datetime)
sqlite3.register_converter("TIMESTAMP", _convert_timestamp)

logger = logging.getLogger("picoshogun.DB")


# ─── Abstract connection interface for future Postgres migration ────────
class ConnectionPool:
    """Abstract interface for database connection pooling.

    The current SQLite implementation uses thread-local connections.
    For a Postgres migration, implement this interface with
    ``asyncpg`` or ``psycopg`` connection pooling.
    """

    def acquire(self):
        """Get a connection from the pool."""
        raise NotImplementedError

    def release(self, conn):
        """Return a connection to the pool."""
        raise NotImplementedError

    def close_all(self):
        """Close all connections in the pool."""
        raise NotImplementedError


@dataclass
class Migration:
    version: int
    name: str
    sql: str

MIGRATIONS = [
    Migration(1, "initial", """
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
    """),

    Migration(2, "add_users", """
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
    """),

    Migration(3, "add_audit_log", """
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
    """),

    Migration(4, "add_webhooks_scheduler", """
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
    """),

    Migration(5, "add_orgs", """
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
    """),

    Migration(6, "add_org_id_to_runs_and_revoked_at", """
        -- Add org_id column to project_runs (P0 fix: get_usage() crashed)
        -- Using IF NOT EXISTS pattern via try/except at Python level for SQLite compat

        -- Add revoked_at column to api_keys (P1 fix: rotate_api_key crashed)
        -- Same: handled idempotently

        -- Add index for org-filtered run queries
        CREATE INDEX IF NOT EXISTS idx_project_runs_org ON project_runs(org_id, run_start);
    """),
    Migration(7, "add_anomaly_alerts", """
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
    """),

    Migration(8, "orgs_api_key_to_hash", """
        -- No-op: column rename handled in Python _migrate_orgs_api_key_hash()
        -- This placeholder ensures migration 8 is recorded as applied.
        SELECT 1;
    """),

    Migration(9, "add_correlation_events", """
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
    """)]


class DatabaseManager:
    """Thread-safe database manager with connection pooling.

    Uses SQLitePool by default. Switch to PostgresPool by setting
    PICOSHOGUN_DATABASE_BACKEND=postgres and PICOSHOGUN_DATABASE_URL.
    """

    def __init__(self, db_path: Path | None = None, backend: str | None = None):
        self._backend = backend or settings.database.backend
        self._pool = create_pool(backend=self._backend, db_path=db_path)
        self._lock = self._pool.lock() if isinstance(self._pool, SQLitePool) else threading.Lock()
        self._init_migrations()

    @property
    def db_path(self) -> Path:
        """Database path (SQLite only). Returns Path('') for other backends."""
        if isinstance(self._pool, SQLitePool):
            return self._pool.db_path
        return Path("")

    @property
    def backend(self) -> str:
        """Active database backend ('sqlite' or 'postgres')."""
        return self._backend

    def _get_connection(self):
        """Get a connection from the pool."""
        return self._pool.acquire()

    @contextmanager
    def transaction(self):
        """Context manager for database transactions.

        Yields the connection so callers can execute statements
        directly on it (e.g. ``with db.transaction() as conn:``).
        """
        conn = self._get_connection()
        try:
            conn.execute("BEGIN")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def execute(self, sql: str, params: tuple = ()) -> list:
        """Execute SQL and return results as a list of dicts.

        The connection's ``row_factory`` is ``sqlite3.Row`` (set in
        ``pools.py``), but most call sites in the serve layer expect a
        dict-like API (``row['col']``, ``(row or {}).get('col')``).
        ``sqlite3.Row`` doesn't implement ``.get()``, so we materialize
        rows as plain dicts at this boundary. Bracket access works on
        both, so this change is source-compatible with every existing
        call site.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute(sql, params)
            return [dict(r) for r in cursor.fetchall()]

    def execute_one(self, sql: str, params: tuple = ()) -> dict | None:
        """Execute SQL and return first result as a dict (or ``None``)."""
        results = self.execute(sql, params)
        return results[0] if results else None

    def execute_insert(self, sql: str, params: tuple = ()) -> int:
        """Execute INSERT and return last row ID."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute(sql, params)
            conn.commit()
            return cursor.lastrowid

    def _migrate_orgs_api_key_hash(self):
        """Rename api_key column to api_key_hash if needed (migration 8)."""
        # Check if orgs table exists
        try:
            cols = self.execute("PRAGMA table_info(orgs)")
            if not cols:
                return  # Table doesn't exist yet
            col_names = [row["name"] for row in cols]
            if "api_key" in col_names and "api_key_hash" not in col_names:
                # SQLite 3.25+ supports RENAME COLUMN
                self.execute("ALTER TABLE orgs RENAME COLUMN api_key TO api_key_hash")
                logger.info("Renamed orgs.api_key → orgs.api_key_hash")
            elif "api_key" in col_names and "api_key_hash" in col_names:
                # Both columns exist (shouldn't happen) — drop the old one
                # SQLite doesn't support DROP COLUMN before 3.35.0, so recreate
                logger.warning("Both api_key and api_key_hash exist in orgs — skipping rename")
        except Exception as e:
            # Fresh install or table doesn't exist — nothing to do
            logger.debug("orgs migration check skipped: %s", e)

    def _init_migrations(self):
        """Initialize and run pending migrations."""
        self.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                name TEXT
            )
        """)

        current_version = self.execute_one(
            "SELECT MAX(version) as v FROM schema_version"
        )
        current = current_version["v"] if current_version and current_version["v"] is not None else 0

        for migration in MIGRATIONS:
            if migration.version > current:
                logger.info("Applying migration %s: %s", migration.version, migration.name)
                for stmt in migration.sql.split(";"):
                    stmt = stmt.strip()
                    if stmt:
                        try:
                            self.execute(stmt + ";")
                        except Exception as e:
                            # Allow idempotent migration: ignore duplicate column/index errors
                            err_str = str(e).lower()
                            if "duplicate column" in err_str or "already exists" in err_str:
                                logger.debug("Migration idempotent skip: %s", e)
                            else:
                                raise
                self.execute_insert(
                    "INSERT INTO schema_version (version, name) VALUES (?, ?)",
                    (migration.version, migration.name)
                )
                logger.info("Migration %s applied", migration.version)
        # Post-migration: rename api_key column if needed
        self._migrate_orgs_api_key_hash()

    def backup(self) -> Path:
        """Create a backup of the database (SQLite only)."""
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
        """Close all connections in the pool."""
        self._pool.close_all()

# Global instance
db = DatabaseManager()
