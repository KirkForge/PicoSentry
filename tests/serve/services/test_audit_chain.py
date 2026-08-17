"""Audit hash chain lives in the DB, not in process memory (B9).

A second DatabaseManager on the same file (a second worker or a restart)
must extend the same linear chain, and verify_audit_chain must report the
first break when a row is tampered with or a fork is spliced in.
"""

from __future__ import annotations


from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.services.audit_chain import append_audit_row, verify_audit_chain


def _row(i: int):
    return {
        "action": "GET",
        "user_id": i,
        "resource_type": "api",
        "resource_id": f"/thing/{i}",
        "details": {"method": "GET", "path": f"/thing/{i}", "status_code": 200},
        "ip_address": "127.0.0.1",
        "user_agent": "pytest",
    }


def test_chain_stays_linear_across_manager_instances(tmp_path):
    db1 = DatabaseManager(db_path=tmp_path / "audit.db")
    assert append_audit_row(**_row(1), database=db1)
    assert append_audit_row(**_row(2), database=db1)

    # A "second worker" / restart: fresh manager, same file.
    db2 = DatabaseManager(db_path=tmp_path / "audit.db")
    assert append_audit_row(**_row(3), database=db2)

    rows = db2.execute("SELECT id, prev_hash, row_hash FROM audit_log ORDER BY id")
    assert len(rows) == 3
    assert rows[0]["prev_hash"] == ""
    assert rows[1]["prev_hash"] == rows[0]["row_hash"]
    assert rows[2]["prev_hash"] == rows[1]["row_hash"]
    assert len({r["row_hash"] for r in rows}) == 3

    result = verify_audit_chain(database=db2)
    assert result["valid"] is True
    assert result["rows_checked"] == 3


def test_verify_detects_tampered_row(tmp_path):
    mgr = DatabaseManager(db_path=tmp_path / "audit.db")
    append_audit_row(**_row(1), database=mgr)
    append_audit_row(**_row(2), database=mgr)
    append_audit_row(**_row(3), database=mgr)

    mgr.execute("UPDATE audit_log SET details = ? WHERE id = 2", ('{"tampered": true}',))

    result = verify_audit_chain(database=mgr)
    assert result["valid"] is False
    assert result["row_id"] == 2
    assert "row_hash" in result["violation"]


def test_verify_detects_forked_chain(tmp_path):
    """Two rows claiming the same predecessor — what multi-worker used to do."""
    mgr = DatabaseManager(db_path=tmp_path / "audit.db")
    append_audit_row(**_row(1), database=mgr)
    append_audit_row(**_row(2), database=mgr)

    # Splice in a rogue row that links to row 1 instead of row 2.
    fork_prev = mgr.execute_one("SELECT row_hash FROM audit_log WHERE id = 1")["row_hash"]
    mgr.execute(
        """
        INSERT INTO audit_log (action, user_id, resource_type, resource_id, details,
            ip_address, user_agent, prev_hash, row_hash, org_id, severity)
        VALUES ('GET', 99, 'api', '/rogue', '{}', '127.0.0.1', 'pytest', ?, 'forkhash', NULL, 'default')
    """,
        (fork_prev,),
    )

    result = verify_audit_chain(database=mgr)
    assert result["valid"] is False
    assert result["row_id"] == 3
    assert "prev_hash" in result["violation"]


def test_verify_org_scoped_and_limit(tmp_path):
    mgr = DatabaseManager(db_path=tmp_path / "audit.db")
    for i in range(4):
        append_audit_row(**_row(i), org_id=1 if i % 2 else 2, database=mgr)

    scoped = verify_audit_chain(org_id=1, database=mgr)
    assert scoped["valid"] is True
    assert scoped["rows_checked"] == 2

    tail = verify_audit_chain(limit=2, database=mgr)
    assert tail["valid"] is True
    assert tail["rows_checked"] == 2


def test_legacy_unhashed_rows_do_not_break_verify(tmp_path):
    """Rows written before migration 11 (empty hashes) are skipped, and the
    chain resumes cleanly after them."""
    mgr = DatabaseManager(db_path=tmp_path / "audit.db")
    mgr.execute(
        """
        INSERT INTO audit_log (action, user_id, resource_type, resource_id, details,
            ip_address, user_agent, prev_hash, row_hash, org_id, severity)
        VALUES ('GET', 0, 'api', '/legacy', '{}', NULL, NULL, '', '', NULL, 'default')
    """
    )
    assert append_audit_row(**_row(1), database=mgr)

    result = verify_audit_chain(database=mgr)
    assert result["valid"] is True
    assert result["rows_checked"] == 2


def test_severity_persisted_on_append(tmp_path):
    mgr = DatabaseManager(db_path=tmp_path / "audit.db")
    append_audit_row(**_row(1), severity="critical", database=mgr)
    row = mgr.execute_one("SELECT severity FROM audit_log WHERE id = 1")
    assert row["severity"] == "critical"
