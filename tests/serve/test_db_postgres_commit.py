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
        self._lock = threading.Lock()

    def acquire(self):
        return self._conn

    def close_all(self):
        pass

    def lock(self):
        return self._lock


def _pg_manager(conn):
    mgr = DatabaseManager.__new__(DatabaseManager)
    mgr._backend = "postgres"
    mgr._pool = _FakePGPool(conn)
    mgr._lock = mgr._pool.lock()
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
