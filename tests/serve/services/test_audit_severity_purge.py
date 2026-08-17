"""Per-severity audit retention (B4): DEFAULT_RETENTION is actually enforced."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.services.audit_cleanup import SQLITE_TS, get_audit_stats, purge_audit_logs


@pytest.fixture
def purge_db(tmp_path, monkeypatch):
    """Isolated manager patched in as the audit_cleanup module's DB."""
    import picosentry.serve.services.audit_cleanup as cleanup_mod

    mgr = DatabaseManager(db_path=tmp_path / "audit.db")
    monkeypatch.setattr(cleanup_mod, "db", mgr)
    return mgr


def _insert(mgr: DatabaseManager, *, severity: str, age_days: int, org_id: int | None = None) -> None:
    created = datetime.now(timezone.utc) - timedelta(days=age_days)
    mgr.execute(
        """
        INSERT INTO audit_log (action, user_id, resource_type, resource_id, details,
            ip_address, user_agent, prev_hash, row_hash, org_id, severity, created_at)
        VALUES ('GET', 1, 'api', '/x', '{}', NULL, NULL, '', '', ?, ?, ?)
    """,
        (org_id, severity, created.strftime(SQLITE_TS)),
    )


def _counts_by_severity(mgr: DatabaseManager) -> dict[str, int]:
    # Purges append a chained `audit.purge` gap-marker row (WO4.0.0-004) —
    # these assertions are about retained DATA rows, so markers are excluded.
    rows = mgr.execute("SELECT severity, COUNT(*) as c FROM audit_log WHERE action != 'audit.purge' GROUP BY severity")
    return {r["severity"]: r["c"] for r in rows}


def test_default_policy_purges_per_severity(purge_db):
    _insert(purge_db, severity="critical", age_days=200)  # survives (365d retention)
    _insert(purge_db, severity="high", age_days=200)  # gone (180d)
    _insert(purge_db, severity="medium", age_days=200)  # gone (90d)
    _insert(purge_db, severity="low", age_days=31)  # gone (30d)
    _insert(purge_db, severity="low", age_days=10)  # survives
    _insert(purge_db, severity="default", age_days=200)  # gone (90d)

    result = purge_audit_logs()

    assert result["low"]["deleted"] == 1
    assert result["critical"]["deleted"] == 0
    assert _counts_by_severity(purge_db) == {"critical": 1, "low": 1}


def test_dry_run_counts_per_severity(purge_db):
    _insert(purge_db, severity="low", age_days=31)
    _insert(purge_db, severity="low", age_days=31)
    _insert(purge_db, severity="critical", age_days=31)  # within 365d → untouched

    result = purge_audit_logs(dry_run=True)

    assert result["low"]["would_delete"] == 2
    assert result["critical"]["would_delete"] == 0
    assert _counts_by_severity(purge_db) == {"low": 2, "critical": 1}


def test_explicit_retention_days_override_single_cutoff(purge_db):
    _insert(purge_db, severity="critical", age_days=40)
    _insert(purge_db, severity="low", age_days=40)
    _insert(purge_db, severity="low", age_days=10)

    result = purge_audit_logs(retention_days=30)

    assert result["deleted"] == 2
    assert _counts_by_severity(purge_db) == {"low": 1}


def test_org_scoped_purge_leaves_other_org(purge_db):
    _insert(purge_db, severity="low", age_days=200, org_id=1)
    _insert(purge_db, severity="low", age_days=200, org_id=2)

    purge_audit_logs(org_id=1)

    # Data rows only; the purge's own gap-marker row (org 1) is excluded.
    rows = purge_db.execute("SELECT org_id FROM audit_log WHERE action != 'audit.purge'")
    assert [r["org_id"] for r in rows] == [2]


def test_stats_advertise_enforced_policy(purge_db):
    _insert(purge_db, severity="low", age_days=1)
    stats = get_audit_stats()
    assert stats["total_entries"] == 1
    assert stats["retention_policy"]["critical"] == 365
