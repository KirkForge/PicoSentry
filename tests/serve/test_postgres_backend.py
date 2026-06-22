"""Tests for PostgreSQL backend support in the database manager.

These tests validate the SQLite-to-Postgres SQL translation helpers and the
SQLDialect abstraction.  They do not require a running Postgres server; the
PostgresPool import guard is exercised separately via the optional psycopg2
dependency.
"""

import pytest

from picosentry.serve.database.manager import (
    Migration,
    SQLDialect,
    _sqlite_to_postgres,
)


class TestSQLiteToPostgresTranslation:
    def test_autoincrement_to_serial(self):
        sqlite = "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);"
        pg = _sqlite_to_postgres(sqlite)
        assert "SERIAL PRIMARY KEY" in pg
        assert "AUTOINCREMENT" not in pg

    def test_placeholders_translated(self):
        sqlite = "INSERT INTO t (a, b) VALUES (?, ?)"
        pg = _sqlite_to_postgres(sqlite)
        assert pg == "INSERT INTO t (a, b) VALUES (%s, %s)"

    def test_literal_question_mark_not_a_risk(self):
        """Project-controlled migration SQL has no literal '?'."""
        sqlite = "SELECT * FROM t WHERE name = ?"
        assert _sqlite_to_postgres(sqlite) == "SELECT * FROM t WHERE name = %s"


class TestMigrationBackendSelection:
    def test_sqlite_backend_uses_sqlite_sql(self):
        m = Migration(
            version=1,
            name="test",
            sqlite_sql="CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT);",
            postgres_sql="CREATE TABLE t (id SERIAL PRIMARY KEY);",
        )
        assert "AUTOINCREMENT" in m.sql_for("sqlite")

    def test_postgres_backend_prefers_explicit_sql(self):
        m = Migration(
            version=1,
            name="test",
            sqlite_sql="CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT);",
            postgres_sql="CREATE TABLE t (id SERIAL PRIMARY KEY);",
        )
        sql = m.sql_for("postgres")
        assert "SERIAL PRIMARY KEY" in sql
        assert "AUTOINCREMENT" not in sql

    def test_postgres_backend_auto_translates_when_no_explicit(self):
        m = Migration(
            version=1,
            name="test",
            sqlite_sql="CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT);",
        )
        sql = m.sql_for("postgres")
        assert "SERIAL PRIMARY KEY" in sql
        assert "INTEGER PRIMARY KEY AUTOINCREMENT" not in sql


class TestSQLDialect:
    @pytest.mark.parametrize(
        ("backend", "expected"),
        [
            ("sqlite", "?"),
            ("postgres", "%s"),
        ],
    )
    def test_placeholder(self, backend, expected):
        assert SQLDialect(backend).placeholder() == expected

    def test_date_now_sqlite(self):
        assert SQLDialect("sqlite").date_now() == "DATE('now')"

    def test_date_now_postgres(self):
        assert SQLDialect("postgres").date_now() == "CURRENT_DATE"

    def test_date_column_sqlite(self):
        assert SQLDialect("sqlite").date_column("run_start") == "DATE(run_start)"

    def test_date_column_postgres(self):
        assert SQLDialect("postgres").date_column("run_start") == "run_start::date"

    def test_hour_column_sqlite(self):
        assert SQLDialect("sqlite").hour_column("created_at") == "strftime('%H', created_at)"

    def test_hour_column_postgres(self):
        assert SQLDialect("postgres").hour_column("created_at") == "EXTRACT(HOUR FROM created_at)::text"

    def test_date_add_hours_sqlite(self):
        assert SQLDialect("sqlite").date_add_hours("now", -24) == "datetime('now', '-24 hours')"

    def test_date_add_hours_postgres(self):
        assert SQLDialect("postgres").date_add_hours("now", -24) == "NOW() + INTERVAL '-24 hours'"

    def test_bool_true_sqlite(self):
        assert SQLDialect("sqlite").bool_true() == 1

    def test_bool_true_postgres(self):
        assert SQLDialect("postgres").bool_true() is True

    def test_unsupported_backend_uses_sqlite_defaults(self):
        d = SQLDialect("unknown")
        assert d.placeholder() == "?"
        assert d.date_now() == "DATE('now')"
        assert d.date_column("col") == "DATE(col)"
