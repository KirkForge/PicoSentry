"""WO-013: scoped locking for read paths; WO-020: boot migration race.

The DatabaseManager's statement lock is a readers/writer lock: concurrent
reads no longer serialize behind each other (per-thread connections make
that safe), while writes keep exclusivity. Migration version inserts are
conflict-tolerant so racing workers booting on a fresh DB converge instead
of dying on the schema_version primary key.
"""

from __future__ import annotations

import threading
import time

from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.database.pools import ReadWriteLock


class TestReadWriteLock:
    def test_reads_share_the_lock(self):
        lock = ReadWriteLock()
        second_entered = threading.Event()

        def _second_reader():
            with lock.read():
                second_entered.set()

        with lock.read():
            t = threading.Thread(target=_second_reader)
            t.start()
            assert second_entered.wait(5), "concurrent read was blocked by a reader"
        t.join(timeout=5)
        assert second_entered.is_set()

    def test_write_excludes_readers(self):
        lock = ReadWriteLock()
        read_acquired = threading.Event()

        def _reader():
            with lock.read():
                read_acquired.set()

        with lock.write():
            t = threading.Thread(target=_reader)
            t.start()
            # Negative wait: the reader must NOT get in while we write.
            assert not read_acquired.wait(0.3), "reader acquired the lock during a write"
        t.join(timeout=5)
        assert read_acquired.wait(5), "reader never acquired the lock after the write released"

    def test_writer_prefers_pending_writers(self):
        """A pending writer blocks new readers (no writer starvation)."""
        lock = ReadWriteLock()
        write2_acquired = threading.Event()
        late_read_acquired = threading.Event()

        def _writer2():
            with lock.write():
                write2_acquired.set()

        def _late_reader():
            with lock.read():
                late_read_acquired.set()

        with lock.read():
            w = threading.Thread(target=_writer2)
            w.start()
            assert not write2_acquired.wait(0.2), "writer acquired while a reader held the lock"

            r = threading.Thread(target=_late_reader)
            r.start()
            # The late reader queues behind the pending writer.
            assert not late_read_acquired.wait(0.2), "late reader jumped past a pending writer"

        w.join(timeout=5)
        assert write2_acquired.wait(5)
        r.join(timeout=5)
        assert late_read_acquired.wait(5)


class TestStatementLockScoping:
    def test_select_takes_shared_insert_takes_exclusive(self, tmp_path, monkeypatch):
        from contextlib import contextmanager

        mgr = DatabaseManager(db_path=tmp_path / "scoped.db", backend="sqlite")
        used: list[str] = []
        real_read, real_write = mgr._lock.read, mgr._lock.write

        @contextmanager
        def _spy_read():
            used.append("read")
            with real_read():
                yield

        @contextmanager
        def _spy_write():
            used.append("write")
            with real_write():
                yield

        monkeypatch.setattr(mgr._lock, "read", _spy_read)
        monkeypatch.setattr(mgr._lock, "write", _spy_write)

        mgr.execute("SELECT 1")
        mgr.execute_insert(
            "INSERT INTO alerts (project_id, alert_type, severity, message) VALUES (?, ?, ?, ?)",
            ("p", "t", "info", "m"),
        )
        assert used == ["read", "write"], "SELECT must share; INSERT must be exclusive"

    def test_concurrent_reads_and_writes_complete(self, tmp_path):
        mgr = DatabaseManager(db_path=tmp_path / "mixed.db", backend="sqlite")
        done = threading.Event()
        errors: list[Exception] = []

        def _reader():
            try:
                for _ in range(50):
                    mgr.execute("SELECT COUNT(*) AS c FROM alerts")
            except Exception as exc:  # recorded and re-asserted below
                errors.append(exc)
            finally:
                done.set()

        readers = [threading.Thread(target=_reader) for _ in range(3)]
        for t in readers:
            t.start()
        for i in range(20):
            mgr.execute_insert(
                "INSERT INTO alerts (project_id, alert_type, severity, message) VALUES (?, ?, ?, ?)",
                ("p", "t", "info", str(i)),
            )
        assert done.wait(10)
        for t in readers:
            t.join(timeout=5)
        assert not errors, errors


class TestMigrationBootRace:
    def test_second_manager_on_same_db_boots_cleanly(self, tmp_path):
        """Two DatabaseManager instances (stand-ins for two workers) on one
        database file must both finish _init_migrations without raising."""
        path = tmp_path / "race.db"
        DatabaseManager(db_path=path, backend="sqlite")
        DatabaseManager(db_path=path, backend="sqlite")  # second "worker"

    def test_schema_version_insert_is_conflict_tolerant(self, tmp_path):
        """The version insert survives a duplicate-key race (ON CONFLICT DO
        NOTHING) instead of crashing the loser's boot."""
        mgr = DatabaseManager(db_path=tmp_path / "conflict.db", backend="sqlite")
        sql = "INSERT INTO schema_version (version, name) VALUES (?, ?) ON CONFLICT (version) DO NOTHING"
        mgr.execute(sql, (999_001, "race-winner"))
        mgr.execute(sql, (999_001, "race-loser"))  # must not raise
        rows = mgr.execute("SELECT COUNT(*) AS c FROM schema_version WHERE version = 999001")
        assert rows[0]["c"] == 1


class TestRateLimitFlushAtomicity:
    """WO-020: the persisted DELETE+re-INSERT runs as one transaction — a
    crash mid-flush must leave the previous counters in place, not a
    window with none."""

    def _middleware(self, monkeypatch):
        from starlette.applications import Starlette
        from starlette.responses import PlainTextResponse
        from starlette.routing import Route

        from picosentry.serve.middleware.rate_limit import RateLimitMiddleware

        async def _ok(request):
            return PlainTextResponse("ok")

        star = Starlette(routes=[Route("/{p:path}", _ok, methods=["GET"])])
        mw = RateLimitMiddleware(star, persist=True, exempt_paths=set())
        return mw

    def test_flush_writes_counters(self, monkeypatch):
        from picosentry.serve.database.manager import db as app_db

        mw = self._middleware(monkeypatch)
        try:
            mw.ip_requests["1.2.3.4"] = [time.time() - 1]
            mw._flush_to_db()
            rows = app_db.execute("SELECT bucket_key FROM rate_limit_counters WHERE bucket_type = 'ip'")
            assert [r["bucket_key"] for r in rows] == ["1.2.3.4"]
            app_db.execute("DELETE FROM rate_limit_counters")
        finally:
            mw.shutdown()

    def test_failed_flush_rolls_back_to_previous_state(self, monkeypatch):
        """A crash between the DELETE and the INSERTs must roll back — the
        old rows survive instead of leaving the table empty.

        WO6.0.0-010: the flush now CATCHES operational DB errors (RuntimeError
        is in _DB_SOFT_ERRORS) and degrades to memory-only instead of
        propagating — so the assertion is that _flush_to_db returns normally
        and the previous counters survive via transaction rollback.
        """
        from picosentry.serve.database.manager import db as app_db

        mw = self._middleware(monkeypatch)
        mw.ip_requests["1.2.3.4"] = [time.time() - 1]
        mw._flush_to_db()  # seed the table with the "previous" state
        mw.ip_requests.clear()
        mw.ip_requests["5.6.7.8"] = [time.time() - 1]

        original = app_db.execute_on
        calls = {"n": 0}

        def _boom_on_second_insert(conn, sql, params=()):
            calls["n"] += 1
            if calls["n"] == 2:  # first INSERT of the new flush (after the DELETE)
                raise RuntimeError("disk died mid-flush")
            return original(conn, sql, params)

        monkeypatch.setattr(app_db, "execute_on", _boom_on_second_insert)
        # WO6.0.0-010: flush catches the error (degrade to memory-only), does
        # not propagate — the transaction still rolls back so the old row survives.
        try:
            mw._flush_to_db()

            rows = app_db.execute("SELECT bucket_key FROM rate_limit_counters WHERE bucket_type = 'ip'")
            assert [r["bucket_key"] for r in rows] == ["1.2.3.4"], "mid-flush crash left counters deleted"
            app_db.execute("DELETE FROM rate_limit_counters")
        finally:
            mw.shutdown()
