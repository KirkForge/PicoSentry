import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from picosentry.serve.api.deps import get_current_org, require_permission
from picosentry.serve.database.manager import db
from picosentry.serve.services.orchestrator import orchestrator
from picosentry.serve.services.rbac import Permission

logger = logging.getLogger("picoshogun.dashboard")

router = APIRouter()


@router.get("/dashboard/summary", tags=["Dashboard"])
async def dashboard_summary(
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.READ_DASHBOARD)),
):
    status = orchestrator.get_status(org_id=org["id"])
    health = orchestrator.get_health_checks()
    recent_projects = orchestrator.list_projects(limit=10)
    recent_intel = db.execute(
        "SELECT id, source_project, intel_type, severity, confidence, created_at "
        "FROM intelligence WHERE org_id = ? ORDER BY created_at DESC LIMIT 10",
        (org["id"],),
    )
    recent_alerts = db.execute(
        "SELECT id, project_id, alert_type, severity, message, channel, sent, created_at "
        "FROM alerts WHERE org_id = ? ORDER BY created_at DESC LIMIT 10",
        (org["id"],),
    )
    pending_alerts = db.execute_one("SELECT COUNT(*) as c FROM alerts WHERE sent = 0 AND org_id = ?", (org["id"],))
    health_overall = "healthy"
    if any(c["status"] == "critical" for c in health):
        health_overall = "critical"
    elif any(c["status"] in ("warning", "degraded") for c in health):
        health_overall = "degraded"
    return {
        "status": status,
        "health": {"overall": health_overall, "checks": health},
        "recent_projects": [dict(p) for p in recent_projects],
        "recent_intelligence": [dict(i) for i in recent_intel] if recent_intel else [],
        "recent_alerts": [dict(a) for a in recent_alerts] if recent_alerts else [],
        "pending_alerts_count": pending_alerts["c"] if pending_alerts else 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
