"""WO6.0.0-010 regression: persistence failure contracts.

sqlite3.OperationalError (the exact error busy_timeout=15s produces) is a
subclass of NEITHER OSError NOR ValueError. Three "best-effort" persistence
paths caught the wrong tuple and turned DB contention into request failures
(500 after a 15s stall) or orphaned project_runs rows. These tests prove the
correct exception classes are now caught and the request/run row survives.
"""

from __future__ import annotations

import sqlite3
import time
from unittest.mock import MagicMock

from picosentry.serve.middleware.rate_limit import RateLimitMiddleware, _DB_SOFT_ERRORS


class _LockHeldFakeDb:
    """Simulates a sqlite busy_timeout expiry on the shared counter table.

    The transaction() raises OperationalError ("database is locked") as a
    real 15s-timeout holder would; execute() for the restore SELECT returns
    an empty result so __init__ doesn't blow up.
    """

    def __init__(self):
        self.backend = "sqlite"

    def execute(self, sql, params=()):
        if "CREATE TABLE" in sql:
            return []
        if "SELECT bucket_type, bucket_key, timestamps" in sql:
            return []
        return []

    def execute_one(self, sql, params=()):
        return None

    def execute_insert(self, sql, params=()):
        return 0

    def execute_on(self, conn, sql, params=()):
        return []

    def transaction(self, immediate=True):
        raise sqlite3.OperationalError("database is locked")


def test_rate_limit_flush_under_held_lock_does_not_raise(monkeypatch):
    """WO6.0.0-010 (1): the background flush catching OperationalError must
    degrade to memory-only, not propagate. The request path never sees the
    contention — it records and returns 429/200 without a 15s stall."""
    fake_db = _LockHeldFakeDb()
    monkeypatch.setattr("picosentry.serve.database.manager.db", fake_db)

    m = RateLimitMiddleware(app=None, max_requests_per_ip=5, window=60, persist=True, sync_interval=0.1)
    try:
        now = time.time()
        key = "locked-single"
        for i in range(5):
            limited, _ = m._record_and_check("ip", key, 5, now + i * 0.001, m.ip_requests)
            assert not limited, f"request {i} unexpectedly limited"
        # The 6th request for the same bucket is limited (memory-only still
        # works — the flush failure did not break the request path).
        limited, _ = m._record_and_check("ip", key, 5, now + 0.01, m.ip_requests)
        assert limited, "in-memory limit broken by flush failure"
    finally:
        m.shutdown()


def test_db_soft_errors_includes_sqlite_operational_error():
    """WO6.0.0-010: OperationalError (busy_timeout product error) must be in
    the caught tuple — it is a subclass of sqlite3.Error, not OSError or
    ValueError."""
    assert issubclass(sqlite3.OperationalError, _DB_SOFT_ERRORS)
    assert sqlite3.Error in _DB_SOFT_ERRORS


def test_outbox_persist_catches_sqlite_error(monkeypatch):
    """WO6.0.0-010 (2): EventBus._persist_outbox must catch sqlite3.Error
    (was catching only OSError/RuntimeError/ValueError via _POLL_ERRORS).
    A locked outbox INSERT must not propagate out of publish()."""
    from picosentry.serve.services.event_bus import EventBus

    bus = EventBus()
    bus.outbox_enabled = True

    class _LockedDb:
        def execute_insert(self, sql, params=()):
            raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr("picosentry.serve.database.manager.db", _LockedDb())

    # Must not raise — publish() is best-effort on the outbox path.
    seen = []
    bus.subscribe("outbox.locked", seen.append)
    event = bus.publish("outbox.locked", {"v": 1})
    assert len(seen) == 1, "local delivery lost because outbox persist raised"
    assert seen[0].id == event.id


def test_started_event_publish_failure_does_not_orphan_run_row(monkeypatch, tmp_path):
    """WO6.0.0-010 (3): the project.run.started publish sits BEFORE the try
    block on base — an outbox persist failure there 500s /run and orphans
    the project_runs row 'running' forever. Moving it inside the guarded
    section means the except path marks the row 'failed' instead."""
    from picosentry.serve.services import orchestrator as orch_mod
    from picosentry.serve.services.orchestrator import EnhancedOrchestrator, ProjectMeta

    monkeypatch.setenv("PICOSHOGUN_DATABASE_PATH", str(tmp_path / "orch.db"))
    orch = EnhancedOrchestrator()
    orch.registry["test-project"] = ProjectMeta(
        id="test-project",
        name="Test Project",
        category="scan",
        priority=1,
        dependencies=[],
        cron_schedule="",
        estimated_duration=1,
        status="active",
        version="1.0.0",
    )

    publish_mock = MagicMock()
    monkeypatch.setattr(orch_mod.event_bus, "publish", publish_mock)
    monkeypatch.setattr(orch_mod.plugin_manager, "dispatch", MagicMock())
    orch.alerts.send = MagicMock()

    # Only the started-event publish raises (the one that sat outside the try
    # on base). The failed-event publish inside the except handler must
    # succeed so the row is marked 'failed' and the error is reported.
    def _publish_side_effect(event_type, *a, **kw):
        if event_type == "project.run.started":
            raise RuntimeError("started publish exploded (outbox locked)")
        return MagicMock()

    publish_mock.side_effect = _publish_side_effect
    monkeypatch.setattr(
        orch_mod.subprocess,
        "run",
        MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr="")),
    )

    result = orch.run_project("test-project")

    # The run row must NOT be orphaned 'running' — the except path marked it.
    assert "error" in result, f"publish failure escaped the guarded section: {result}"
    from picosentry.serve.database.manager import db

    rows = db.execute(
        "SELECT status FROM project_runs WHERE project_id = ? ORDER BY id DESC LIMIT 1",
        ("test-project",),
    )
    assert rows, "no project_runs row was created"
    assert rows[0]["status"] == "failed", f"run row orphaned as '{rows[0]['status']}' instead of 'failed'"
