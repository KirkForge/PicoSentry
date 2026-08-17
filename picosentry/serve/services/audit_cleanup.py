import logging
from datetime import datetime, timedelta, timezone

from picosentry.serve.database.manager import db

logger = logging.getLogger("picoshogun.AuditRetention")

SQLITE_TS = "%Y-%m-%d %H:%M:%S"


DEFAULT_RETENTION: dict[str, int] = {
    "critical": 365,  # 1 year for critical events
    "high": 180,  # 6 months for high
    "medium": 90,  # 90 days for medium
    "low": 30,  # 30 days for low
    "default": 90,  # 90 days for everything else
}


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

        db.execute(f"DELETE FROM audit_log WHERE created_at < ?{org_clause}", (cutoff.strftime(SQLITE_TS), *org_params))
        row = db.execute_one("SELECT changes() as c")
        total = row["c"] if row else 0
        logger.info("Purged %d audit log entries older than %d days", total, retention_days)
        return {"deleted": total, "cutoff": cutoff.isoformat()}

    results = {}
    for severity, days in DEFAULT_RETENTION.items():
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        if dry_run:
            row = db.execute_one(
                f"SELECT COUNT(*) as c FROM audit_log WHERE created_at < ?{org_clause}",
                (cutoff.strftime(SQLITE_TS), *org_params),
            )
            results[severity] = {"would_delete": row["c"] if row else 0, "cutoff": cutoff.isoformat()}
        else:
            db.execute(
                f"DELETE FROM audit_log WHERE created_at < ?{org_clause}", (cutoff.strftime(SQLITE_TS), *org_params)
            )
            row = db.execute_one("SELECT changes() as c")
            total = row["c"] if row else 0
            results[severity] = {"deleted": total, "cutoff": cutoff.isoformat()}
            logger.info("Purged %d audit log entries (severity: %s, retention: %d days)", total, severity, days)

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
