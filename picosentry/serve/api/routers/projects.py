"""Project, intelligence, alert, and report endpoints."""
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from picosentry.serve.api.deps import get_current_user, require_role
from picosentry.serve.api.models import AlertResponse, BatchRunRequest, IntelligenceItem, ProjectRunRequest, ProjectStatus
from picosentry.serve.database.manager import db
from picosentry.serve.services.orchestrator import orchestrator

logger = logging.getLogger("picoshogun.projects")

router = APIRouter()




@router.get("/projects", response_model=list[ProjectStatus], tags=["Projects"])
async def list_projects(
    category: str | None = Query(None),
    status: str | None = Query(None),
    user: dict = Depends(get_current_user),
):
    """List all projects with optional category/status filtering."""
    projects = orchestrator.list_projects()
    if category:
        projects = [p for p in projects if p.get("category") == category]
    if status:
        projects = [p for p in projects if p.get("status") == status]
    return projects


@router.get("/projects/{project_id}", response_model=ProjectStatus, tags=["Projects"])
async def get_project(
    project_id: str,
    user: dict = Depends(get_current_user),
):
    """Get details for a specific project."""
    project = orchestrator.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found")
    return project


@router.post("/projects/{project_id}/run", tags=["Projects"])
async def run_project(
    project_id: str,
    request: ProjectRunRequest | None = None,
    user: dict = Depends(require_role("operator")),
):
    """Trigger a project run (operator+ required)."""
    timeout = request.timeout if request else 300
    result = orchestrator.run_project(project_id, timeout=timeout)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/batch/run", tags=["Projects"])
async def run_batch(
    request: BatchRunRequest,
    user: dict = Depends(require_role("operator")),
):
    """Run multiple projects in batch (operator+ required)."""
    results = {}
    for pid in request.project_ids:
        result = orchestrator.run_project(pid, timeout=request.timeout or 300)
        results[pid] = result if "error" not in result else {"error": result["error"]}
    return results


@router.get("/projects/{project_id}/export", tags=["Projects"])
async def export_project(
    project_id: str,
    format: str = Query("json", pattern="^(json|csv)$"),
    user: dict = Depends(get_current_user),
):
    """Export project data as JSON or CSV."""
    project = orchestrator.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found")

    if format == "csv":
        import io

        from fastapi.responses import PlainTextResponse
        output = io.StringIO()
        if project.get("findings"):
            import csv
            writer = csv.DictWriter(output, fieldnames=project["findings"][0].keys())
            writer.writeheader()
            writer.writerows(project["findings"])
        return PlainTextResponse(content=output.getvalue(), media_type="text/csv")

    return project


@router.get("/intelligence", response_model=list[IntelligenceItem], tags=["Intelligence"])
async def list_intelligence(
    source_project: str | None = Query(None),
    intel_type: str | None = Query(None),
    severity: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: dict = Depends(get_current_user),
):
    """List intelligence entries with optional filtering."""
    query = "SELECT * FROM intelligence WHERE 1=1"
    params: list[Any] = []
    if source_project:
        query += " AND source_project = ?"
        params.append(source_project)
    if intel_type:
        query += " AND intel_type = ?"
        params.append(intel_type)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    rows = db.execute(query, tuple(params))
    return [dict(r) for r in rows] if rows else []


@router.get("/intelligence/correlations/{project_id}", tags=["Intelligence"])
async def get_correlations(project_id: str, user: dict = Depends(get_current_user)):
    """Get correlation data for a project's intelligence entries."""
    rows = db.execute(
        "SELECT * FROM intelligence WHERE source_project = ? ORDER BY created_at DESC",
        (project_id,),
    )
    return {"project_id": project_id, "correlations": [dict(r) for r in rows] if rows else []}


@router.get("/intelligence/threat-score", tags=["Intelligence"])
async def get_threat_score(user: dict = Depends(get_current_user)):
    """Aggregate threat score from intelligence."""
    result = db.execute_one("SELECT AVG(confidence) as avg_score, COUNT(*) as total FROM intelligence WHERE severity IN ('critical', 'high')")
    return {
        "threat_score": round(result["avg_score"], 3) if result and result["avg_score"] else 0.0,
        "total_threats": result["total"] if result else 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/alerts", response_model=list[AlertResponse], tags=["Alerts"])
async def list_alerts(
    severity: str | None = Query(None),
    project_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: dict = Depends(get_current_user),
):
    """List alerts with optional severity/project filtering."""
    query = "SELECT * FROM alerts WHERE 1=1"
    params: list[Any] = []
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if project_id:
        query += " AND project_id = ?"
        params.append(project_id)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    rows = db.execute(query, tuple(params))
    return [dict(r) for r in rows] if rows else []


@router.post("/alerts/{alert_id}/acknowledge", tags=["Alerts"])
async def acknowledge_alert(alert_id: int, user: dict = Depends(get_current_user)):
    """Acknowledge (mark as read) an alert."""
    # Check alert exists first
    alert = db.execute_one("SELECT id FROM alerts WHERE id = ?", (alert_id,))
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    db.execute_insert("UPDATE alerts SET sent = 1 WHERE id = ?", (alert_id,))
    return {"status": "acknowledged", "alert_id": alert_id}


@router.get("/reports/summary", tags=["Reports"])
async def get_summary_report(user: dict = Depends(get_current_user)):
    """Aggregated summary report across all projects."""
    projects = orchestrator.list_projects()
    total = len(projects)
    active = sum(1 for p in projects if p.get("status") == "active")
    failed = sum(1 for p in projects if p.get("status") == "failed")
    return {
        "total_projects": total,
        "active_projects": active,
        "failed_projects": failed,
        "success_rate": round(active / max(total, 1), 2),
    }


@router.get("/reports/project/{project_id}", tags=["Reports"])
async def get_project_report(project_id: str, user: dict = Depends(get_current_user)):
    """Detailed report for a specific project."""
    project = orchestrator.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found")
    return project
