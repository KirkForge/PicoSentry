"""WO6.0.0-020: multi-worker riders.

Gate tests:
1. add_job cross-org TOCTOU: two orgs racing one name → loser's fallback
   re-checks org and raises ValueError (not the winner's id with 201).
2. deps off the loop: require_org_membership is sync def (threadpooled by
   FastAPI), not async def wrapping a blocking DB read.
3. SIGTERM stops the outbox poller (server.main() graceful handler calls
   _stop_outbox_poller, matching the lifespan teardown).
4. PG connections pin UTC at acquire (skipped if psycopg2 unavailable).
"""

from __future__ import annotations

import inspect
import threading
import time

import pytest

from picosentry.serve.services.scheduler import JobScheduler


def _fresh_scheduler() -> JobScheduler:
    s = JobScheduler()
    s.lease_ttl = 15
    s._tick_sleep = 0.05
    return s


class TestAddJobCrossOrgTOCTOU:
    def test_in_tx_select_re_checks_org(self):
        """WO6.0.0-020 item 4: _insert_job_atomic's in-tx SELECT (the
        fallback for the boot-race) must re-check org. Pre-fix it returned
        the WINNER's id without checking org — org B racing org A's name
        got 201 with org A's job id. Post-fix the cross-org guard raises."""
        a = _fresh_scheduler()
        b = _fresh_scheduler()
        name = f"toctou_{time.time_ns()}"
        # Org A wins: inserts first via the normal add_job path.
        a.add_job(name=name, cron="* * * * *", command="cleanup", params={}, org_id=1)
        # Org B's _insert_job_atomic sees org A's row in the in-tx SELECT
        # (the boot-race fallback path) — must re-check org and raise.
        with pytest.raises(ValueError, match="already in use by another organization"):
            b._insert_job_atomic(
                name=name, cron="* * * * *", command="cleanup", params_json="{}", enabled=True, org_id=2
            )

    def test_integrity_error_fallback_re_checks_org(self, monkeypatch):
        """The IntegrityError fallback path (postgres: loser's INSERT fails
        on the unique index after the winner commits) must re-check org
        before returning the existing id. We force the INSERT to raise an
        IntegrityError so the fallback runs against a pre-inserted org A row."""
        from picosentry.serve.database import manager as mgr_mod

        a = _fresh_scheduler()
        b = _fresh_scheduler()
        name = f"toctou2_{time.time_ns()}"
        a.add_job(name=name, cron="* * * * *", command="cleanup", params={}, org_id=1)

        # Force the in-tx INSERT to raise an IntegrityError so the fallback
        # path runs. The in-tx SELECT returns org A's row; the fallback must
        # re-check org and raise rather than return org A's id.
        import sqlite3

        orig_execute_on = mgr_mod.db.execute_on

        def _fail_insert(conn, sql, params=()):
            if "INSERT INTO scheduled_jobs" in sql:
                raise sqlite3.IntegrityError("UNIQUE constraint failed: scheduled_jobs.name")
            return orig_execute_on(conn, sql, params)

        monkeypatch.setattr(mgr_mod.db, "execute_on", _fail_insert)
        with pytest.raises(ValueError, match="already in use by another organization"):
            b._insert_job_atomic(
                name=name, cron="* * * * *", command="cleanup", params_json="{}", enabled=True, org_id=2
            )

    def test_same_org_converges_on_existing_id(self):
        """Sanity: the same org re-calling add_job for an existing name
        (same config) returns the existing id, not an error. This is the
        boot-race convergence the atomic insert was built for."""
        a = _fresh_scheduler()
        name = f"converge_{time.time_ns()}"
        job_id_1 = a.add_job(name=name, cron="* * * * *", command="cleanup", params={}, org_id=1)
        job_id_2 = a.add_job(name=name, cron="* * * * *", command="cleanup", params={}, org_id=1)
        assert job_id_1 == job_id_2


class TestDepsOffTheLoop:
    def test_require_org_membership_is_sync(self):
        """WO6.0.0-020 item 3: require_org_membership must be a sync def
        (FastAPI threadpools sync deps); an async def wrapping a blocking
        DB read blocks the event loop."""
        from picosentry.serve.api import deps

        assert not inspect.iscoroutinefunction(deps.require_org_membership), (
            "require_org_membership is async def — it blocks the event loop on its DB read; make it sync def"
        )


class TestSigtermStopsPoller:
    def test_graceful_shutdown_calls_stop_outbox_poller(self, monkeypatch):
        """WO6.0.0-020 item 1: the SIGTERM handler in server.main() must
        call _stop_outbox_poller() — post-`db.close()` the poller re-opens
        connections and keeps polling during the shutdown window."""

        from picosentry.serve.api import server

        # The handler is a closure inside main(); verify the module exposes
        # _stop_outbox_poller and that calling it is idempotent (the lifespan
        # also calls it). The handler's behavior is: stop poller, stop
        # anomaly/scheduler/event_bus/plugins, close db, SystemExit.
        called = {"stop": False}
        orig = server._stop_outbox_poller

        def _tracked_stop():
            called["stop"] = True
            orig()

        monkeypatch.setattr(server, "_stop_outbox_poller", _tracked_stop)
        # Invoke the handler the way signal would: it's defined inside main(),
        # so we re-extract the behavior by checking the module-level stop is
        # callable and idempotent. The real assertion is that main()'s handler
        # references _stop_outbox_poller (verified by source inspection below).
        server._stop_outbox_poller()
        assert called["stop"]

        # Source-level: main()'s _graceful_shutdown must call _stop_outbox_poller.
        import picosentry.serve.api.server as srv_mod

        source = inspect.getsource(srv_mod.main)
        assert "_stop_outbox_poller" in source, "SIGTERM handler does not stop the outbox poller"


class TestPGTimezonePinning:
    def test_pg_acquire_pins_utc(self):
        """WO6.0.0-020 item 6: PostgresPool.acquire() must SET TIMEZONE 'UTC'
        on every fresh connection (quota-day CURRENT_DATE boundaries and lease
        expires_at comparisons are correct only if all sessions share one TZ).
        Verified with a fake psycopg2 conn recording executed statements —
        the CI postgres-live job covers the real path end-to-end."""
        import contextlib

        class _FakeCursor:
            def __init__(self, statements):
                self._statements = statements

            def execute(self, sql, params=()):
                self._statements.append(sql)

        class _FakePGConn:
            def __init__(self, statements):
                self._statements = statements
                self.autocommit = False
                self.closed = False

            def cursor(self):
                return _FakeCursor(self._statements)

            def close(self):
                pass

        class _FakePsycopg2:
            Error = type("Error", (Exception,), {})

            @staticmethod
            def connect(url, connect_timeout=5):  # noqa: ARG004
                return _FakePGConn(statements)

        # PostgresPool.acquire() calls _ensure_psycopg2() which imports
        # psycopg2; inject the fake before acquire() runs.
        import weakref

        from picosentry.serve.database import pools as pools_mod

        pool = pools_mod.PostgresPool.__new__(pools_mod.PostgresPool)
        pool._url = "postgresql://localhost/test"
        pool._local = threading.local()
        pool._psycopg2 = None
        pool._extras = None
        pool._conns_lock = threading.Lock()
        pool._all_conns = weakref.WeakSet()

        # Stub _ensure_psycopg2 to install the fake.
        def _ensure_fake():
            pool._psycopg2 = _FakePsycopg2()

        pool._ensure_psycopg2 = _ensure_fake

        statements: list[str] = []
        conn = pool.acquire()
        assert any("SET TIMEZONE" in s and "UTC" in s for s in statements), (
            f"acquire() did not SET TIMEZONE 'UTC'; statements: {statements}"
        )
        # autocommit restored to False after the SET (the manager expects
        # autocommit=False for its implicit-transaction hygiene).
        assert conn.autocommit is False
        with contextlib.suppress(Exception):
            pool.close_all()
