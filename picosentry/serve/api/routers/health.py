import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse, JSONResponse

from picosentry.serve.api.deps import get_current_org, get_current_user
from picosentry.serve.api.models import (
    HealthHistoryResponse,
    HealthReadiness,
    LivenessResponse,
    SystemStatus,
)
from picosentry.serve.config.version import __version__
from picosentry.serve.services.orchestrator import orchestrator

logger = logging.getLogger("picoshogun.health")

router = APIRouter()


@router.get("/", tags=["Health"], response_class=HTMLResponse)
async def root():
    from picosentry.serve.api.server import _docs_url

    docs_link = ' · <a href="/docs" style="color:#00ff88">API Docs</a>' if _docs_url else ""
    return f"""<!DOCTYPE html>
<html><head><title>PicoShogun</title></head>
<body style="font-family:monospace;background:#0a0a0a;color:#e0e0e0;display:flex;\
justify-content:center;align-items:center;height:100vh;margin:0">
<div style="text-align:center">
<h1 style="color:#00ff88">⚔️ PicoShogun</h1>
<p>Security Command Centre — v{__version__}</p>
<p style="color:#888"><a href="/dashboard" style="color:#00ff88">Dashboard</a>{docs_link} · \
<a href="/health" style="color:#00ff88">Health</a></p>
</div></body></html>"""


@router.get("/dashboard", tags=["Dashboard"], response_class=HTMLResponse)
async def dashboard():
    from pathlib import Path

    base = Path(__file__).resolve().parent.parent.parent / "front"

    dashboard_path = base / "build" / "index.html"
    if not dashboard_path.exists():
        dashboard_path = base / "index.html"
    if dashboard_path.exists():
        return dashboard_path.read_text()
    return f"""<!DOCTYPE html>
<html><head><title>PicoShogun Dashboard</title></head>
<body style="font-family:monospace;background:#0a0a0a;color:#e0e0e0;display:flex;\
justify-content:center;align-items:center;height:100vh;margin:0">
<div style="text-align:center">
<h1 style="color:#00ff88">⚔️ Dashboard</h1>
<p>PicoShogun v{__version__}</p>
<p style="color:#888">Dashboard not found — expected <code>front/build/index.html</code> \
or <code>front/index.html</code></p>
</div></body></html>"""


@router.get("/health", response_model=HealthReadiness, tags=["Health"])
async def health_check():
    health = orchestrator.get_health_checks()
    overall = "healthy"
    if any(c["status"] == "critical" for c in health):
        overall = "critical"
    elif any(c["status"] in ("warning", "degraded") for c in health):
        overall = "degraded"
    return HealthReadiness(
        overall=overall,
        checks=health,
        timestamp=datetime.now(timezone.utc),
    )


@router.get("/health/live", tags=["Health"], response_model=LivenessResponse)
async def liveness_probe():
    return {"status": "alive"}


@router.get("/health/ready", tags=["Health"], response_model=None)
async def readiness_probe():

    checks: dict[str, str] = {}
    ready = True

    try:
        from picosentry.serve.database.manager import db

        db.execute_one("SELECT 1")
        checks["database"] = "ok"
    except (OSError, ValueError, RuntimeError):
        checks["database"] = "unavailable"
        ready = False

    try:
        from picosentry.serve.services.plugin_manager import plugin_manager

        checks["plugins"] = "loaded" if plugin_manager.plugins else "ok"
    except (OSError, ValueError, RuntimeError):
        checks["plugins"] = "not_loaded"
        ready = False

    if ready:
        return {"status": "ready"}
    return JSONResponse(status_code=503, content={"status": "not ready", "checks": checks})


@router.get("/health/history", tags=["Health"], response_model=list[HealthHistoryResponse])
async def health_history(limit: int = Query(50, ge=1, le=1000), user: dict = Depends(get_current_user)):
    from picosentry.serve.database.manager import db as _db

    rows = _db.execute(
        "SELECT * FROM health_checks ORDER BY created_at DESC LIMIT ?",
        (limit,),
    )
    result = []
    for r in rows or []:
        item = dict(r)
        if item.get("created_at") is not None:
            item["created_at"] = item["created_at"].isoformat()
        result.append(item)
    return result


@router.get("/status", response_model=SystemStatus, tags=["Status"])
async def get_status(
    user: dict = Depends(get_current_user),
    org: dict = Depends(get_current_org),
):
    status_data = orchestrator.get_status(org_id=org["id"])
    health = orchestrator.get_health_checks()
    threat_score = 0.0
    if health:
        threat_score = sum(h.get("latency_ms", 0) for h in health) / max(len(health), 1)

    return SystemStatus(
        projects_total=status_data.get("projects_total", 0),
        projects_active=status_data.get("projects_active", 0),
        projects_failed=status_data.get("projects_failed", 0),
        active_threats=status_data.get("active_threats", 0),
        pending_alerts=status_data.get("pending_alerts", 0),
        threat_score=threat_score,
        system_health=status_data.get("system_health", "unknown"),
        uptime_seconds=status_data.get("uptime_seconds", 0.0),
        timestamp=datetime.now(timezone.utc),
    )
