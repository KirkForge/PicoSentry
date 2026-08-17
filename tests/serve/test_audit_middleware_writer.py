"""Audit middleware background-writer contract (probe S11).

Rows land (poll via done-events), a full queue drops loudly with a monotonic
counter, and the single writer thread preserves append order (the hash chain
stays linear).
"""

from __future__ import annotations

import logging
import threading

from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.middleware.audit import _AuditWriter, _get_writer


def _fields(mgr: DatabaseManager, action: str) -> dict:
    return {
        "action": action,
        "user_id": 1,
        "resource_type": "api",
        "resource_id": f"/x/{action}",
        "details": {"n": 1},
        "ip_address": None,
        "user_agent": None,
        "severity": "default",
        "org_id": None,
        "database": mgr,
    }


class TestRowsLand:
    def test_rows_land_in_submit_order(self, tmp_path):
        mgr = DatabaseManager(db_path=tmp_path / "audit.db", backend="sqlite")
        writer = _AuditWriter()
        dones = [writer.submit(_fields(mgr, f"act{i}")) for i in range(5)]
        assert all(d is not None and d.wait(5) for d in dones)
        rows = mgr.execute("SELECT action FROM audit_log ORDER BY id")
        assert [r["action"] for r in rows] == [f"act{i}" for i in range(5)]

    def test_request_writes_audit_row(self, client):
        from picosentry.serve.database.manager import db

        _get_writer()  # ensure the singleton writer exists
        resp = client.get("/health/live")
        assert resp.status_code == 200
        # The bounded dispatch wait makes the row durable before the response.
        row = db.execute_one(
            "SELECT action FROM audit_log WHERE resource_id = ? ORDER BY id DESC LIMIT 1",
            ("/health/live",),
        )
        assert row is not None
        assert row["action"] == "GET"


class TestFullQueueDropsLoudly:
    def test_full_queue_drops_counts_and_warns(self, monkeypatch, caplog):
        from picosentry.serve.services import audit_chain

        entered = threading.Event()
        release = threading.Event()

        def _blocking_append(**_kwargs):
            entered.set()
            assert release.wait(5)

        monkeypatch.setattr(audit_chain, "append_audit_row", _blocking_append)

        writer = _AuditWriter(maxsize=1)
        first = writer.submit({"action": "x"})
        assert first is not None
        assert entered.wait(5)  # writer took the item; queue is empty again
        second = writer.submit({"action": "y"})
        assert second is not None  # occupies the single slot

        with caplog.at_level(logging.WARNING, logger="picoshogun.Audit"):
            dropped = writer.submit({"action": "z"})
        assert dropped is None
        assert writer.dropped == 1
        assert "dropping row" in caplog.text

        release.set()
        assert second.wait(5)
