"""Regression tests for EventBus exception narrowing (P4 #10)."""

from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timedelta, timezone

import pytest

from picosentry.serve.services.event_bus import EventBus, OutboxPoller


class TestEventBusExceptionNarrowing:
    """Subscriber failures must be isolated, but programmer errors must propagate."""

    def test_operational_handler_error_is_isolated(self, caplog):
        bus = EventBus()
        calls = []

        def _good(event):
            calls.append(event)

        def _bad(event):
            raise RuntimeError("subscriber operational failure")

        bus.subscribe("test.event", _good)
        bus.subscribe("test.event", _bad)

        with caplog.at_level("ERROR", logger="picoshogun.EventBus"):
            bus.publish("test.event", {"payload": 1})

        assert len(calls) == 1
        assert "subscriber operational failure" in caplog.text

    def test_unexpected_handler_error_propagates(self):
        bus = EventBus()

        def _bad(event):
            raise NameError("programmer bug")

        bus.subscribe("test.event", _bad)
        with pytest.raises(NameError, match="programmer bug"):
            bus.publish("test.event", {"payload": 1})

    def test_later_subscribers_still_run_after_operational_error(self, caplog):
        bus = EventBus()
        calls = []

        def _bad(event):
            raise ValueError("bad subscriber")

        def _good(event):
            calls.append(event)

        bus.subscribe("test.event", _bad)
        bus.subscribe("test.event", _good)

        with caplog.at_level("ERROR", logger="picoshogun.EventBus"):
            bus.publish("test.event", {"payload": 1})

        assert len(calls) == 1


# ---------------------------------------------------------------------------
# WO6.0.0-009: outbox poller correctness (naive timestamps, prune, liveness,
# side-effect demultiplexing).
# ---------------------------------------------------------------------------


class _FakePgDb:
    """Simulates psycopg2 returning naive datetimes for a TIMESTAMP (no tz)
    column — the exact condition that killed the poller on postgres.

    Returns foreign outbox rows with naive created_at; the poller must coerce
    them to tz-aware before comparing against _started_at.
    """

    def __init__(self, rows):
        self._rows = rows
        self._tx = False

    def execute_one(self, sql, params=()):
        if "MAX(seq)" in sql:
            return {"seq": 0}
        return None

    def execute(self, sql, params=()):
        if "FROM event_outbox WHERE seq >" in sql:
            last = params[0] if params else 0
            return [r for r in self._rows if int(r["seq"]) > last]
        if "DELETE FROM event_outbox" in sql:
            return []
        return []

    def transaction(self, immediate=True):
        class _Ctx:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        return _Ctx()

    def execute_on(self, conn, sql, params=()):
        return []


def test_poller_survives_naive_postgres_timestamps(monkeypatch):
    """WO6.0.0-009: naive created_at (pg TIMESTAMP no tz) must not kill the
    poller via TypeError on the timestamp comparison. The poller coerces at
    the DB boundary and dispatches the foreign row."""
    bus = EventBus()
    seen = []
    bus.subscribe("foreign.event", seen.append)

    naive_ts = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=5)
    fake_rows = [
        {
            "seq": 1,
            "id": "evt-1",
            "type": "foreign.event",
            "source": "other-worker",
            "payload": '{"v": 1}',
            "priority": "normal",
            "org_id": None,
            "worker_id": "other:1234:abcd",
            "created_at": naive_ts,
        }
    ]
    fake_db = _FakePgDb(fake_rows)
    monkeypatch.setattr("picosentry.serve.database.manager.db", fake_db)

    poller = OutboxPoller(bus, interval=0.05, retention_seconds=3600)
    poller.start()
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not seen:
            time.sleep(0.05)
        assert len(seen) == 1, f"foreign row with naive timestamp not dispatched: {seen}"
        assert seen[0].id == "evt-1"
        assert seen[0].timestamp.tzinfo is not None, "naive timestamp not coerced to tz-aware"
        assert poller.is_alive(), "poller died on naive-timestamp foreign row"
    finally:
        poller.stop()


def test_poller_survives_prune_under_write_lock(monkeypatch):
    """WO6.0.0-009: sqlite3.OperationalError from a prune DELETE under a
    held BEGIN IMMEDIATE write lock must NOT kill the poller — it is in
    _POLL_ERRORS now and the next tick retries."""
    bus = EventBus()

    class _LockHeldDb(_FakePgDb):
        def __init__(self):
            super().__init__(rows=[])

        def execute(self, sql, params=()):
            if "DELETE FROM event_outbox" in sql:
                raise sqlite3.OperationalError("database is locked")
            return super().execute(sql, params)

    fake_db = _LockHeldDb()
    monkeypatch.setattr("picosentry.serve.database.manager.db", fake_db)

    poller = OutboxPoller(bus, interval=0.05, retention_seconds=3600)
    poller._last_prune = None
    poller.start()
    try:
        time.sleep(0.3)
        assert poller.is_alive(), "poller died on prune OperationalError"
        assert poller.last_error is None, f"unexpected poller death: {poller.last_error}"
    finally:
        poller.stop()


def test_poller_liveness_drops_on_thread_exit(monkeypatch):
    """WO6.0.0-009: when the poller thread dies on an uncaught error,
    is_alive() returns False and last_error records the cause — so /metrics
    can surface the death instead of the thread vanishing silently."""
    bus = EventBus()

    class _DeadlyDb(_FakePgDb):
        def __init__(self):
            super().__init__(rows=[])

        def execute(self, sql, params=()):
            if "FROM event_outbox WHERE seq >" in sql:
                raise NameError("programmer bug — must propagate, kills thread")
            return super().execute(sql, params)

    fake_db = _DeadlyDb()
    monkeypatch.setattr("picosentry.serve.database.manager.db", fake_db)

    poller = OutboxPoller(bus, interval=0.05, retention_seconds=3600)
    poller.start()
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and poller.is_alive():
            time.sleep(0.05)
        assert not poller.is_alive(), "poller did not die on uncaught NameError"
        assert poller.last_error is not None
        assert "NameError" in poller.last_error
    finally:
        poller.stop()


def test_foreign_row_skips_local_only_subscribers():
    """WO6.0.0-009: foreign (outbox-polled) rows must dispatch to history +
    ordinary subscribers (WS) but SKIP local_only side-effect subscribers —
    the publishing worker already fired escalation; without the skip every
    worker re-fires it Nx."""
    bus = EventBus()
    plain_seen = []
    side_effect_seen = []

    bus.subscribe("demux.event", plain_seen.append)
    bus.subscribe("demux.event", side_effect_seen.append, local_only=True)

    # Local publish: both fire.
    local_evt = bus.publish("demux.event", {"who": "local"})
    assert len(plain_seen) == 1
    assert len(side_effect_seen) == 1

    # Foreign row via _dispatch with skip_local_only=True: only plain fires.
    foreign_evt = type(local_evt)(
        id="foreign-1",
        type="demux.event",
        source="other",
        payload={"who": "foreign"},
        timestamp=datetime.now(timezone.utc),
    )
    bus._dispatch(foreign_evt, skip_local_only=True)
    assert len(plain_seen) == 2
    assert len(side_effect_seen) == 1, "local_only subscriber re-fired for foreign row"
    assert any(e.id == "foreign-1" for e in bus.get_history("demux.event", limit=50))
