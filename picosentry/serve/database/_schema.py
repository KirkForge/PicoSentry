from __future__ import annotations

from dataclasses import dataclass


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


@dataclass
class Migration:
    version: int
    name: str
    sqlite_sql: str
    postgres_sql: str | None = None

    def sql_for(self, backend: str) -> str:
        if backend == "sqlite":
            return self.sqlite_sql
        if self.postgres_sql is None:
            # ponytail: no silent string-replace fallback. Per-backend migration
            # SQL is mandatory; a missing postgres_sql is a programmer error that
            # would otherwise ship SQLite DDL to Postgres via regex munging.
            raise RuntimeError(
                f"migration {self.version} ({self.name}) has no postgres_sql; per-backend migration SQL is mandatory"
            )
        return self.postgres_sql


MIGRATIONS: list[Migration] = [
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
        # table is not created until migration 5, so the sqlite SQL above cannot be
        # auto-translated for Postgres. We omit the project_runs -> orgs FK here
        # and create the equivalent index; referential integrity is enforced by
        # application code for the nullable org_id column.
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
        postgres_sql="""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'viewer',
            is_active BOOLEAN DEFAULT TRUE,
            last_login TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id SERIAL PRIMARY KEY,
            key_hash TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            name TEXT,
            permissions TEXT,
            expires_at TIMESTAMP,
            last_used TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE,
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
        postgres_sql="""
        CREATE TABLE IF NOT EXISTS audit_log (
            id SERIAL PRIMARY KEY,
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
        postgres_sql="""
        CREATE TABLE IF NOT EXISTS webhooks (
            id SERIAL PRIMARY KEY,
            name TEXT,
            url TEXT NOT NULL,
            secret TEXT,
            events TEXT,
            active BOOLEAN DEFAULT TRUE,
            retries INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scheduled_jobs (
            id SERIAL PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            cron_expression TEXT NOT NULL,
            command TEXT NOT NULL,
            params TEXT DEFAULT '{}',
            enabled BOOLEAN DEFAULT TRUE,
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
        postgres_sql="""
        CREATE TABLE IF NOT EXISTS orgs (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            owner_id INTEGER,
            tier TEXT DEFAULT 'free',
            api_key_hash TEXT UNIQUE,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS org_users (
            id SERIAL PRIMARY KEY,
            org_id INTEGER,
            user_id INTEGER,
            role TEXT DEFAULT 'member',
            invited_at TIMESTAMP,
            joined_at TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS org_projects (
            id SERIAL PRIMARY KEY,
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
        postgres_sql="""
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
        postgres_sql="""
        CREATE TABLE IF NOT EXISTS anomaly_alerts (
            id SERIAL PRIMARY KEY,
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
        postgres_sql="""
        -- No-op: column rename handled in Python _migrate_orgs_api_key_hash()
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
        postgres_sql="""
        CREATE TABLE IF NOT EXISTS correlation_events (
            id SERIAL PRIMARY KEY,
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
            id SERIAL PRIMARY KEY,
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
        # Postgres supports ADD COLUMN IF NOT EXISTS (PG >= 9.6), which makes
        # the tenant-tagging migration idempotent without the runner's
        # duplicate-column swallow. SQLite's ALTER TABLE lacks that clause, so
        # the SQLite variant relies on the migration runner's version guard.
        postgres_sql="""
        ALTER TABLE intelligence ADD COLUMN IF NOT EXISTS org_id INTEGER;
        ALTER TABLE alerts ADD COLUMN IF NOT EXISTS org_id INTEGER;
        ALTER TABLE metrics ADD COLUMN IF NOT EXISTS org_id INTEGER;
        ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS org_id INTEGER;
        ALTER TABLE scheduled_jobs ADD COLUMN IF NOT EXISTS org_id INTEGER;
        ALTER TABLE correlation_chains ADD COLUMN IF NOT EXISTS org_id INTEGER;

        CREATE INDEX IF NOT EXISTS idx_intelligence_org ON intelligence(org_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_org ON alerts(org_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_metrics_org ON metrics(org_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_webhooks_org ON webhooks(org_id);
        CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_org ON scheduled_jobs(org_id);
        CREATE INDEX IF NOT EXISTS idx_correlation_chains_org ON correlation_chains(org_id);
    """,
    ),
]

__all__ = [
    "MIGRATIONS",
    "Migration",
    "SQLDialect",
]
