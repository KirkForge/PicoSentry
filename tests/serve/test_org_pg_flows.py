"""WO4.0.0-003: org/auth flows must be portable to the postgres backend.

Two layers:
  - fake-connection tests (no server) prove every statement issued inside
    transaction() goes through execute_on placeholder translation (? -> %s)
    and that RETURNING-based id extraction works;
  - real-singleton tests run the full org flow against whatever backend the
    environment points at (sqlite locally, postgres in the CI pg-live job).
"""

from __future__ import annotations

import threading
import uuid

import pytest

from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.database.pools import ReadWriteLock


class _FakePGCursor:
    def __init__(self, conn: _FakePGConn):
        self._conn = conn
        self.description: list[tuple] | None = None
        self._rows: list[tuple] = []

    def execute(self, sql: str, params: tuple = ()) -> None:
        self.description = None
        self._rows = []
        stmt = " ".join(sql.split())
        self._conn.statements.append(stmt)
        upper = stmt.upper()
        if "SELECT LASTVAL()" in upper:
            self.description = [("lastval",)]
            self._rows = [(1,)]
        elif "RETURNING" in upper or upper.startswith("SELECT"):
            for i, (pattern, cols, rows) in enumerate(self._conn.results):
                if pattern in stmt:
                    self._conn.results.pop(i)
                    self.description = [(c,) for c in cols]
                    self._rows = rows
                    break

    def fetchall(self) -> list[tuple]:
        return list(self._rows)

    def fetchone(self) -> tuple | None:
        return self._rows[0] if self._rows else None


class _FakePGConn:
    def __init__(self):
        self.statements: list[str] = []
        self.commits = 0
        # (statement substring, column names, row tuples) — matched in order
        self.results: list[tuple[str, tuple[str, ...], list[tuple]]] = []

    def cursor(self) -> _FakePGCursor:
        return _FakePGCursor(self)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        pass


class _FakePGPool:
    def __init__(self, conn: _FakePGConn):
        self._conn = conn

    def acquire(self) -> _FakePGConn:
        return self._conn

    def close_all(self) -> None:
        pass


def _pg_manager(conn: _FakePGConn) -> DatabaseManager:
    # Mirrors the DatabaseManager constructor (the manager owns a
    # ReadWriteLock; the pool lends nothing).
    mgr = DatabaseManager.__new__(DatabaseManager)
    mgr._backend = "postgres"
    mgr._pool = _FakePGPool(conn)
    mgr._lock = ReadWriteLock()
    mgr._tx_depth = threading.local()
    return mgr


def _assert_no_qmark_placeholders(conn: _FakePGConn) -> None:
    leaked = [s for s in conn.statements if "?" in s]
    assert leaked == [], f"raw ? placeholder reached postgres: {leaked}"


class TestOrganizationCreateOnPostgres:
    def test_create_uses_translated_placeholders_and_returning(self, monkeypatch: pytest.MonkeyPatch):
        from picosentry.serve.services import orgs

        conn = _FakePGConn()
        conn.results.append(("RETURNING id", ("id",), [(42,)]))
        monkeypatch.setattr(orgs, "db", _pg_manager(conn))

        created = orgs.Organization.create("Acme", "acme", 1)

        assert created == {"org_id": 42, "api_key": created["api_key"]}
        assert any("INSERT INTO orgs" in s and "RETURNING id" in s for s in conn.statements)
        assert any("INSERT INTO org_users" in s for s in conn.statements)
        assert conn.commits >= 1  # transaction commit (+ implicit stmt commits)
        _assert_no_qmark_placeholders(conn)

    def test_add_project_upsert_is_portable(self, monkeypatch: pytest.MonkeyPatch):
        from picosentry.serve.services import orgs

        conn = _FakePGConn()
        monkeypatch.setattr(orgs, "db", _pg_manager(conn))

        orgs.Organization.add_project(7, "proj-1")

        assert any(
            "INSERT INTO org_projects" in s and "ON CONFLICT (org_id, project_id) DO NOTHING" in s
            for s in conn.statements
        )
        _assert_no_qmark_placeholders(conn)


class TestAuthWritesOnPostgres:
    def _service(self, conn: _FakePGConn):
        from picosentry.serve.services.auth import AuthService

        return AuthService(db=_pg_manager(conn))

    def test_create_user_returns_id_via_returning(self):
        conn = _FakePGConn()
        conn.results.append(("RETURNING id", ("id",), [(5,)]))
        svc = self._service(conn)

        assert svc.create_user("alice", "Passw0rd!x") == 5
        assert any("INSERT INTO users" in s and "RETURNING id" in s for s in conn.statements)
        _assert_no_qmark_placeholders(conn)

    def test_purge_revocations_counts_via_returning(self):
        conn = _FakePGConn()
        conn.results.append(("RETURNING id", ("id",), [(1,), (2,), (3,)]))
        svc = self._service(conn)

        assert svc.purge_expired_revocations() == 3
        assert any("DELETE FROM revoked_tokens" in s and "RETURNING id" in s for s in conn.statements)
        _assert_no_qmark_placeholders(conn)

    def test_login_select_and_updates_are_translated(self, monkeypatch: pytest.MonkeyPatch):
        conn = _FakePGConn()
        conn.results.append(
            (
                "FROM users WHERE username",
                ("id", "username", "password_hash", "role", "locked_until", "failed_login_attempts", "totp_secret"),
                [(9, "bob", "hash", "viewer", None, 0, None)],
            )
        )
        svc = self._service(conn)
        monkeypatch.setattr(svc, "_verify_password", lambda pw, ph: True)

        result = svc.login("bob", "whatever")

        assert result["status"] == "ok"
        assert any("SELECT * FROM users" in s for s in conn.statements)
        assert any("UPDATE users SET last_login" in s for s in conn.statements)
        _assert_no_qmark_placeholders(conn)


class TestOrgFlowOnActiveBackend:
    """Full org flow against the configured backend (sqlite here, postgres in CI)."""

    def test_create_key_associate_usage(self):
        from picosentry.serve.services.auth import AuthService
        from picosentry.serve.services.orgs import Organization

        auth = AuthService()
        owner = auth.create_user(f"org-owner-{uuid.uuid4().hex[:8]}", "Passw0rd!x")
        assert owner

        slug = f"org-{uuid.uuid4().hex[:10]}"
        created = Organization.create("Acme", slug, owner)
        assert created and created["org_id"], "org create failed on active backend"

        by_key = Organization.get_by_api_key(created["api_key"])
        assert by_key and by_key["id"] == created["org_id"]

        assert any(m["role"] == "admin" for m in Organization.get_members(created["org_id"]))

        Organization.add_project(created["org_id"], "proj-x")
        Organization.add_project(created["org_id"], "proj-x")

        assert Organization.has_project(created["org_id"], "proj-x")
        usage = Organization.get_usage(created["org_id"])
        assert usage["projects"]["used"] == 1, "duplicate association inflated usage"

    def test_create_duplicate_slug_is_empty_conflict(self):
        from picosentry.serve.services.auth import AuthService
        from picosentry.serve.services.orgs import Organization

        owner = AuthService().create_user(f"org-owner-{uuid.uuid4().hex[:8]}", "Passw0rd!x")
        slug = f"dup-{uuid.uuid4().hex[:10]}"
        assert Organization.create("First", slug, owner)
        assert Organization.create("Second", slug, owner) == {}
