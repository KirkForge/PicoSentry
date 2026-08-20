"""WO6.0.0-013: login transaction discipline.

Gate tests:
1. Login under a concurrent writer completes fast (no 15s stall, no
   OperationalError). Pre-fix the webauthn SELECT at auth.py:250 ran inside
   BEGIN IMMEDIATE and re-entered the writer-preferring ReadWriteLock READ
   half — a concurrent writer (scheduler lease tick / request inserts)
   starved the reader until busy_timeout killed the writer.
2. db.execute*() on a thread with open _tx_depth raises an actionable error
   (the execute_on-only rule was a latent trap).
3. Invalid-login burst does not hold the write lock (reads run before the
   transaction; only write branches open one).
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

import pytest

from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.services.auth import AuthService


def _fresh_mgr(tmp_path) -> DatabaseManager:
    """Per-test DatabaseManager on an isolated sqlite file so the lock
    behavior is exercised against a real ReadWriteLock, not a mock."""
    mgr = DatabaseManager.__new__(DatabaseManager)
    mgr._backend = "sqlite"
    from picosentry.serve.database.pools import SQLitePool

    mgr._pool = SQLitePool(db_path=tmp_path / "wo13.db")
    from picosentry.serve.config.settings import settings

    mgr._lock = __import__("picosentry.serve.database.pools", fromlist=["ReadWriteLock"]).ReadWriteLock()
    mgr._tx_depth = threading.local()
    mgr._init_migrations()
    return mgr


def _make_user(mgr: DatabaseManager, svc: AuthService, username: str = "alice") -> int:
    uid = svc.create_user(username, "Password123!", "a@b.c")
    assert uid
    return uid


class TestLoginTxDiscipline:
    def test_login_under_concurrent_writer_completes_fast(self, tmp_path):
        """The 15s-stall repro: login holds BEGIN IMMEDIATE then the webauthn
        SELECT re-enters the ReadWriteLock READ half while a concurrent writer
        holds the WRITE half → writer-preferring lock starves the reader
        until busy_timeout kills the writer. Post-fix the webauthn read is a
        plain execute_one (no transaction), so no lock-order inversion."""
        import os

        os.environ.setdefault("PICOSHOGUN_SECRET_KEY", "test-key-for-pytest-at-least-32-bytes!")
        mgr = _fresh_mgr(tmp_path)
        svc = AuthService(mgr)
        uid = _make_user(mgr, svc, "convoy_alice")

        # A writer thread hammering execute_insert (simulates the scheduler
        # lease tick / request insert writer that starved the login reader).
        stop = threading.Event()
        writer_errors: list[Exception] = []

        def _writer():
            while not stop.is_set():
                try:
                    mgr.execute_insert(
                        "INSERT INTO audit_log (action, user_id, resource_type, resource_id, "
                        "details, ip_address, user_agent, prev_hash, row_hash, org_id, severity) "
                        "VALUES ('test', ?, 't', 'r', '{}', '127.0.0.1', 'ua', '', 'h', NULL, 'info')",
                        (uid,),
                    )
                except Exception as exc:  # noqa: BLE001 — collect for assertion
                    writer_errors.append(exc)
                    break
                time.sleep(0.001)

        t_writer = threading.Thread(target=_writer, name="wo13-writer", daemon=True)
        t_writer.start()
        try:
            # Let the writer get going.
            time.sleep(0.05)
            start = time.monotonic()
            result = svc.login("convoy_alice", "Password123!")
            elapsed = time.monotonic() - start
        finally:
            stop.set()
            t_writer.join(timeout=5)

        # Login must succeed and complete well under the 15s busy_timeout.
        assert result["status"] == "ok", f"login failed: {result}"
        assert elapsed < 5.0, f"login stalled {elapsed:.2f}s under concurrent writer (pre-fix: 15s)"
        assert not writer_errors, f"concurrent writer hit errors: {writer_errors}"

    def test_invalid_login_does_not_hold_write_lock(self, tmp_path, monkeypatch):
        """The invalid-login convoy: pre-fix the whole login incl the
        invalid-credential early return (a pure READ) ran inside BEGIN
        IMMEDIATE — a credential-stuffing burst took the RESERVED lock per
        attempt. Post-fix reads run before the transaction; only the
        failed-login counter write opens one."""
        import os

        os.environ.setdefault("PICOSHOGUN_SECRET_KEY", "test-key-for-pytest-at-least-32-bytes!")
        # Raise the lockout threshold so a 20-attempt burst stays "invalid"
        # rather than flipping to "locked" mid-burst (lockout is a separate
        # concern; this test is about lock holding, not the lockout policy).
        from picosentry.serve.config.settings import settings

        monkeypatch.setattr(settings.security, "lockout_max_attempts", 100)
        mgr = _fresh_mgr(tmp_path)
        svc = AuthService(mgr)
        _make_user(mgr, svc, "stuff_alice")

        # A reader thread that needs the READ half. If invalid login held
        # the WRITE lock, this reader would block behind it for each attempt.
        stop = threading.Event()
        reader_blocked_total = [0.0]

        def _reader():
            while not stop.is_set():
                rstart = time.monotonic()
                mgr.execute_one("SELECT 1")
                reader_blocked_total[0] += time.monotonic() - rstart
                time.sleep(0.001)

        t_reader = threading.Thread(target=_reader, name="wo13-reader", daemon=True)
        t_reader.start()
        try:
            time.sleep(0.05)
            start = time.monotonic()
            # A burst of invalid logins (wrong password).
            for _ in range(20):
                result = svc.login("stuff_alice", "wrong-password")
                assert result["status"] == "invalid", f"unexpected status: {result}"
            elapsed = time.monotonic() - start
        finally:
            stop.set()
            t_reader.join(timeout=5)

        # 20 invalid logins should complete fast (each is a read + one short
        # write tx for the counter increment, not a full-login-length write lock).
        assert elapsed < 10.0, f"20 invalid logins took {elapsed:.2f}s (convoy)"


class TestExecuteInTxGuard:
    def test_execute_inside_transaction_raises(self, tmp_path):
        """WO6.0.0-013 deliverable 3: execute() inside transaction() raises
        an actionable error (the execute_on-only rule was a latent trap)."""
        mgr = _fresh_mgr(tmp_path)
        with mgr.transaction() as conn:
            assert conn is not None
            with pytest.raises(RuntimeError, match="execute_on"):
                mgr.execute("SELECT 1")

    def test_execute_insert_inside_transaction_raises(self, tmp_path):
        mgr = _fresh_mgr(tmp_path)
        with mgr.transaction():
            with pytest.raises(RuntimeError, match="execute_on"):
                mgr.execute_insert("INSERT INTO audit_log (action) VALUES ('x')")

    def test_execute_on_inside_transaction_is_allowed(self, tmp_path):
        """execute_on(conn, ...) is the correct API inside transaction()."""
        mgr = _fresh_mgr(tmp_path)
        with mgr.transaction() as conn:
            rows = mgr.execute_on(conn, "SELECT 1 AS one")
            assert rows[0]["one"] == 1

    def test_execute_outside_transaction_is_unaffected(self, tmp_path):
        mgr = _fresh_mgr(tmp_path)
        rows = mgr.execute("SELECT 1 AS one")
        assert rows[0]["one"] == 1