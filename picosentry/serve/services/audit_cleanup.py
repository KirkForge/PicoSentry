import json
import logging
from datetime import datetime, timedelta, timezone

from picosentry.serve.database.manager import db

logger = logging.getLogger("picoshogun.AuditRetention")

SQLITE_TS = "%Y-%m-%d %H:%M:%S"

# Keep DELETE ... IN (?) chunks under the SQLite 999-parameter ceiling.
_DELETE_CHUNK = 500


DEFAULT_RETENTION: dict[str, int] = {
    "critical": 365,  # 1 year for critical events
    "high": 180,  # 6 months for high
    "medium": 90,  # 90 days for medium
    "low": 30,  # 30 days for low
    "default": 90,  # 90 days for everything else
}


def _contiguous_runs(ids: list[int]) -> list[list[int]]:
    runs: list[list[int]] = []
    for i in sorted(ids):
        if runs and i == runs[-1][1] + 1:
            runs[-1][1] = i
        else:
            runs.append([i, i])
    return runs


def _delete_ids(ids: list[int], org_id: int | None) -> None:
    """Delete exactly the selected ids and record the gap (WO4.0.0-004).

    The id runs land in a chained ``audit.purge`` row (severity=critical so
    the marker outlives every retention class it can describe) — that row is
    what lets verify_audit_chain() distinguish an authorized gap from a
    deleted link. ponytail: recorded runs, not a per-id table — collapses to
    one range for the common contiguous purge.
    """
    from picosentry.serve.services.audit_chain import append_audit_row

    if not ids:
        return
    with db.transaction(immediate=True) as conn:
        rows = db.execute_on(
            conn,
            "SELECT id FROM audit_log WHERE id IN (" + ",".join("?" for _ in ids) + ")",
            tuple(ids),
        )
        ids = [r["id"] for r in rows]  # re-read inside the write tx: no races
        for start in range(0, len(ids), _DELETE_CHUNK):
            chunk = ids[start : start + _DELETE_CHUNK]
            marks = ",".join("?" for _ in chunk)
            db.execute_on(conn, f"DELETE FROM audit_log WHERE id IN ({marks})", tuple(chunk))

    runs = _contiguous_runs(ids)
    ok = append_audit_row(
        action="audit.purge",
        user_id=None,
        resource_type="audit_log",
        resource_id=f"gap:{runs[0][0]}..{runs[-1][1]}" if runs else "gap:none",
        details={"deleted": len(ids), "gaps": runs, "org_id": org_id},
        ip_address=None,
        user_agent=None,
        severity="critical",
        org_id=org_id,
        database=db,
    )
    if not ok:
        logger.error("Purge deleted %d rows but failed to record the gap marker — verify will flag it", len(ids))


def purge_audit_logs(retention_days: int | None = None, dry_run: bool = False, org_id: int | None = None) -> dict:
    org_clause = " AND org_id = ?" if org_id is not None else ""
    org_params = (org_id,) if org_id is not None else ()

    if retention_days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        if dry_run:
            row = db.execute_one(
                f"SELECT COUNT(*) as c FROM audit_log WHERE created_at < ?{org_clause}",
                (cutoff.strftime(SQLITE_TS), *org_params),
            )
            return {"would_delete": row["c"] if row else 0, "cutoff": cutoff.isoformat()}

        ids = [
            r["id"]
            for r in db.execute(
                f"SELECT id FROM audit_log WHERE created_at < ?{org_clause}",
                (cutoff.strftime(SQLITE_TS), *org_params),
            )
        ]
        _delete_ids(ids, org_id)
        logger.info("Purged %d audit log entries older than %d days", len(ids), retention_days)
        return {"deleted": len(ids), "cutoff": cutoff.isoformat()}

    results = {}
    all_ids: list[int] = []
    for severity, days in DEFAULT_RETENTION.items():
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        if dry_run:
            row = db.execute_one(
                f"SELECT COUNT(*) as c FROM audit_log WHERE created_at < ? AND severity = ?{org_clause}",
                (cutoff.strftime(SQLITE_TS), severity, *org_params),
            )
            results[severity] = {"would_delete": row["c"] if row else 0, "cutoff": cutoff.isoformat()}
        else:
            ids = [
                r["id"]
                for r in db.execute(
                    f"SELECT id FROM audit_log WHERE created_at < ? AND severity = ?{org_clause}",
                    (cutoff.strftime(SQLITE_TS), severity, *org_params),
                )
            ]
            all_ids.extend(ids)
            results[severity] = {"deleted": len(ids), "cutoff": cutoff.isoformat()}
            logger.info(
                "Selected %d audit log entries for purge (severity: %s, retention: %d days)", len(ids), severity, days
            )

    if all_ids:
        _delete_ids(all_ids, org_id)  # one delete + one gap marker per call

    return results


def get_audit_stats(org_id: int | None = None) -> dict:
    org_clause = " WHERE org_id = ?" if org_id is not None else ""
    org_params = (org_id,) if org_id is not None else ()

    total = db.execute_one(f"SELECT COUNT(*) as c FROM audit_log{org_clause}", org_params)
    oldest = db.execute_one(f"SELECT MIN(created_at) as oldest FROM audit_log{org_clause}", org_params)
    newest = db.execute_one(f"SELECT MAX(created_at) as newest FROM audit_log{org_clause}", org_params)

    actions = db.execute(
        f"SELECT action, COUNT(*) as count FROM audit_log{org_clause} GROUP BY action ORDER BY count DESC LIMIT 10",
        org_params,
    )

    return {
        "total_entries": total["c"] if total else 0,
        "oldest_entry": oldest["oldest"] if oldest and oldest["oldest"] else None,
        "newest_entry": newest["newest"] if newest and newest["newest"] else None,
        "top_actions": [dict(a) for a in actions] if actions else [],
        "retention_policy": DEFAULT_RETENTION,
    }


def load_purged_ids(database=None) -> set[int]:
    """Every audit row id removed by an authorized purge (gap markers)."""
    mgr = database or db
    purged: set[int] = set()
    try:
        rows = mgr.execute("SELECT details FROM audit_log WHERE action = 'audit.purge'")
    except Exception:
        logger.exception("Failed to read purge gap markers — treating all gaps as unexplained")
        return purged
    for row in rows:
        try:
            gaps = json.loads(row["details"]).get("gaps") or []
            for lo, hi in gaps:
                purged.update(range(lo, hi + 1))
        except (ValueError, AttributeError, TypeError):
            logger.warning("Malformed purge gap marker skipped: %r", row["details"][:200])
    return purged
