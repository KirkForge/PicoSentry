"""Postgres-path execute() transaction hygiene (probe S9).

No live postgres needed here: a fake autocommit=False connection records
commit/rollback so we can assert every execute() ends its implicit
transaction (DML committed, SELECT snapshots released), that transaction()
semantics are unchanged, and that SQLite (default backend) stays durable.
The CI postgres-live job exercises the real psycopg2 path end-to-end.
"""

from __future__ import annotations

import threading

import pytest

from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.database.pools import ReadWriteLock


class _FakePGCursor:
    def __init__(self, conn):
        self._conn = conn
        self.description = None
        self._rows: list[tuple] = []

    def execute(self, sql, params=()):
        self._conn.statements.append(" ".join(sql.split())[:60])
        if self._conn.fail_next:
            self._conn.fail_next = False
            raise RuntimeError("statement failed")
        verb = sql.strip().split(None, 1)[0].upper() if sql.strip() else ""
        if verb in ("SELECT", "PRAGMA", "WITH"):
            self.description = [("sample",)]
            self._rows = [("value",)]

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _FakePGConn:
    def __init__(self):
        self.statements: list[str] = []
        self.commits = 0
        self.rolls = 0
        self.fail_next = False

    def cursor(self):
        return _FakePGCursor(self)

    def commit(self):
        self.commits += 1
        self.statements.append("<commit>")

    def rollback(self):
        self.rolls += 1
        self.statements.append("<rollback>")


class _FakePGPool:
    param_style = "format"

    def __init__(self, conn):
        self._conn = conn

    def acquire(self):
        return self._conn

    def close_all(self):
        pass


def _pg_manager(conn):
    # Mirrors the DatabaseManager constructor (the manager owns a
    # ReadWriteLock; the pool lends nothing).
    mgr = DatabaseManager.__new__(DatabaseManager)
    mgr._backend = "postgres"
    mgr._pool = _FakePGPool(conn)
    mgr._lock = ReadWriteLock()
    mgr._tx_depth = threading.local()
    return mgr


class TestExecuteEndsImplicitTransaction:
    def test_dml_is_committed_immediately(self):
        conn = _FakePGConn()
        mgr = _pg_manager(conn)
        mgr.execute("UPDATE alerts SET sent = 1 WHERE id = 5")
        assert conn.commits == 1
        assert conn.rolls == 0

    def test_select_rolls_back_to_release_snapshot(self):
        conn = _FakePGConn()
        mgr = _pg_manager(conn)
        rows = mgr.execute("SELECT * FROM users")
        assert rows == [{"sample": "value"}]
        assert conn.rolls == 1
        assert conn.commits == 0

    def test_statement_failure_rolls_back_aborted_tx(self):
        conn = _FakePGConn()
        mgr = _pg_manager(conn)
        conn.fail_next = True
        with pytest.raises(RuntimeError, match="statement failed"):
            mgr.execute("SELECT * FROM users")
        assert conn.rolls == 1

    def test_execute_insert_commits_dml_and_cleans_lastval_tx(self):
        conn = _FakePGConn()
        mgr = _pg_manager(conn)
        value = mgr.execute_insert("INSERT INTO alerts (x) VALUES (1)")
        assert conn.commits == 1  # the DML itself
        assert conn.rolls == 1  # the lastval() SELECT cleanup
        assert value == "value"


class TestTransactionSemanticsUnchanged:
    def test_execute_inside_transaction_does_not_end_it(self):
        conn = _FakePGConn()
        mgr = _pg_manager(conn)
        with mgr.transaction() as tx_conn:
            assert tx_conn is conn
            mgr.execute("UPDATE t SET x = 1")
            assert conn.commits == 0  # transaction() owns the commit
        assert conn.commits == 1
        assert conn.rolls == 0

    def test_rollback_clears_depth_for_lateral_executes(self):
        conn = _FakePGConn()
        mgr = _pg_manager(conn)
        with pytest.raises(ValueError, match="boom"), mgr.transaction():
            mgr.execute("SELECT 1")
            raise ValueError("boom")
        assert conn.rolls == 1
        mgr.execute("UPDATE t SET x = 1")
        assert conn.commits == 1  # depth restored: execute() self-commits again

    def test_nested_transaction_keeps_existing_shape(self):
        conn = _FakePGConn()
        mgr = _pg_manager(conn)
        with mgr.transaction():
            with mgr.transaction():
                mgr.execute("UPDATE t SET x = 1")
            assert conn.commits == 1  # inner exit commits (pre-existing behavior)
            mgr.execute("UPDATE t SET x = 2")
            assert conn.commits == 1  # still inside the outer transaction
        assert conn.commits == 2
        mgr.execute("UPDATE t SET x = 3")
        assert conn.commits == 3


class TestSqliteDefaultBackendUnchanged:
    def test_execute_dml_is_durable_across_reopen(self, tmp_path):
        db_file = tmp_path / "durability.db"
        mgr = DatabaseManager(db_path=db_file, backend="sqlite")
        mgr.execute("CREATE TABLE t (k TEXT)")
        mgr.execute("INSERT INTO t (k) VALUES ('kept')")

        reopened = DatabaseManager(db_path=db_file, backend="sqlite")
        assert reopened.execute_one("SELECT k FROM t")["k"] == "kept"


class _StrictPsycopg2Cursor(_FakePGCursor):
    """Emulates psycopg2 interpolation semantics faithfully.

    psycopg2 runs pyformat interpolation whenever a params argument is
    PRESENT — even an empty tuple — so DDL containing a literal '%'
    (migration CASE ... LIKE '%admin%') dies with IndexError. The fake
    records whether params was actually passed so tests can pin the fix.
    """

    def __init__(self, conn):
        super().__init__(conn)
        self.params_passed: list[bool] = []
        self.executed_sql: list[str] = []

    def execute(self, sql, params=None):
        self.params_passed.append(params is not None)
        self.executed_sql.append(sql)
        if params is not None and "%" in sql and "%s" not in sql:
            # psycopg2 pyformat: a literal '%' that is not a placeholder has
            # no matching params entry -> IndexError (as seen on pg-live CI).
            raise IndexError("tuple index out of range")
        super().execute(sql)


def _strict_conn() -> tuple[_FakePGConn, _StrictPsycopg2Cursor]:
    conn = _FakePGConn()
    cursor = _StrictPsycopg2Cursor(conn)
    conn.cursor = lambda: cursor  # type: ignore[method-assign]
    return conn, cursor


class TestNoParamsNoInterpolation:
    """Regression (WO4.0.0-017 pg-live fix): literal % in DDL must execute bare."""

    def test_ddl_with_literal_percent_executes_without_params(self):
        conn, cursor = _strict_conn()
        mgr = _pg_manager(conn)
        ddl = "CREATE VIEW v AS SELECT CASE WHEN permissions LIKE '%admin%' THEN 'admin' END"
        mgr.execute_on(conn, ddl + ";")
        assert cursor.params_passed[-1] is False

    def test_parameterized_queries_still_pass_params(self):
        conn, cursor = _strict_conn()
        mgr = _pg_manager(conn)
        mgr.execute("SELECT * FROM users WHERE id = %s", ("7",))
        assert cursor.params_passed[-1] is True


class TestBooleanLiteralTranslation:
    """Postgres BOOLEAN columns reject `= 1` (pg-live CI: operator does not
    exist: boolean = integer). _prepare_sql must translate 1/0 literals on
    the four boolean columns; integer columns must stay untouched."""

    def test_where_bool_equals_one_becomes_true(self):
        conn, cursor = _strict_conn()
        mgr = _pg_manager(conn)
        mgr.execute("SELECT * FROM webhooks WHERE active = 1")
        assert "active = TRUE" in cursor.executed_sql[-1]

    def test_where_bool_equals_zero_becomes_false(self):
        conn, cursor = _strict_conn()
        mgr = _pg_manager(conn)
        mgr.execute("UPDATE webhooks SET active = 0 WHERE id = ?", ("5",))
        assert "active = FALSE" in cursor.executed_sql[-1]

    def test_is_active_and_sent_and_enabled_translate(self):
        conn, cursor = _strict_conn()
        mgr = _pg_manager(conn)
        mgr.execute("SELECT id FROM users WHERE is_active = 1 AND sent = 0 AND enabled = 1")
        stmt = cursor.executed_sql[-1]
        assert "is_active = TRUE" in stmt and "sent = FALSE" in stmt and "enabled = TRUE" in stmt

    def test_integer_column_literal_untouched(self):
        conn, cursor = _strict_conn()
        mgr = _pg_manager(conn)
        mgr.execute("SELECT * FROM alerts WHERE retry_count = 1")
        assert "retry_count = 1" in cursor.executed_sql[-1]

    def test_multi_digit_and_neq_operators(self):
        conn, cursor = _strict_conn()
        mgr = _pg_manager(conn)
        mgr.execute("SELECT * FROM t WHERE active = 10 OR active != 1")
        stmt = cursor.executed_sql[-1]
        assert "active = 10" in stmt and "active != TRUE" in stmt
