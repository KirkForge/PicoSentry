import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Path, Query

from picosentry.serve.api.deps import get_current_org, require_permission
from picosentry.serve.api.models import (
    AlertAcknowledgeResponse,
    AlertResponse,
    BatchRunRequest,
    BatchRunResponse,
    CorrelationResponse,
    IntelligenceItem,
    ProjectReportResponse,
    ProjectRunRequest,
    ProjectRunResponse,
    ProjectStatus,
    ReportSummaryResponse,
    ThreatScoreResponse,
)
from picosentry.serve.database.helpers import build_filtered_query
from picosentry.serve.database.manager import db
from picosentry.serve.services.orchestrator import orchestrator
from picosentry.serve.services.rbac import Permission

logger = logging.getLogger("picoshogun.projects")

router = APIRouter()


@router.get("/projects", response_model=list[ProjectStatus], tags=["Projects"])
async def list_projects(
    category: str | None = Query(None),
    status: str | None = Query(None),
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.READ_PROJECTS)),
):
    projects = orchestrator.list_projects(category=category, status_filter=status, org_id=org["id"])
    return projects


@router.get("/projects/{project_id}", response_model=ProjectStatus, tags=["Projects"])
async def get_project(
    project_id: str = Path(max_length=128),
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.READ_PROJECTS)),
):
    project = orchestrator.get_project(project_id, org_id=org["id"])
    if not project:
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found")
    return project


@router.post("/projects/{project_id}/run", response_model=ProjectRunResponse, tags=["Projects"])
async def run_project(
    project_id: str = Path(max_length=128),
    request: ProjectRunRequest | None = None,
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.RUN_PROJECTS)),
):
    timeout = request.timeout if request else 300
    result = orchestrator.run_project(project_id, timeout=timeout, org_id=org["id"])
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/batch/run", response_model=BatchRunResponse, tags=["Projects"])
async def run_batch(
    request: BatchRunRequest,
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.RUN_PROJECTS)),
):
    results = {}
    for pid in request.project_ids:
        result = orchestrator.run_project(pid, timeout=request.timeout or 300, org_id=org["id"])
        results[pid] = result if "error" not in result else {"error": result["error"]}
    return results


@router.get("/projects/{project_id}/export", response_model=ProjectStatus, tags=["Projects"])
async def export_project(
    project_id: str = Path(max_length=128),
    format: str = Query("json", pattern="^(json|csv)$"),
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.READ_PROJECTS)),
):
    project = orchestrator.get_project(project_id, org_id=org["id"])
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
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.READ_INTELLIGENCE)),
):
    query, params = build_filtered_query(
        "intelligence",
        org["id"],
        {"source_project": source_project, "intel_type": intel_type, "severity": severity},
        limit,
    )

    rows = db.execute(query, params)
    return [dict(r) for r in rows] if rows else []


@router.get("/intelligence/correlations/{project_id}", response_model=CorrelationResponse, tags=["Intelligence"])
async def get_correlations(
    project_id: str,
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.READ_INTELLIGENCE)),
):
    rows = db.execute(
        "SELECT * FROM intelligence WHERE source_project = ? AND org_id = ? ORDER BY created_at DESC",
        (project_id, org["id"]),
    )
    return {"project_id": project_id, "correlations": [dict(r) for r in rows] if rows else []}


@router.get("/intelligence/threat-score", response_model=ThreatScoreResponse, tags=["Intelligence"])
async def get_threat_score(
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.READ_INTELLIGENCE)),
):
    result = db.execute_one(
        "SELECT AVG(confidence) as avg_score, COUNT(*) as total "
        "FROM intelligence WHERE severity IN ('critical', 'high') AND org_id = ?",
        (org["id"],),
    )
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
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.READ_ALERTS)),
):
    query, params = build_filtered_query(
        "alerts",
        org["id"],
        {"severity": severity, "project_id": project_id},
        limit,
    )

    rows = db.execute(query, params)
    return [dict(r) for r in rows] if rows else []


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertAcknowledgeResponse, tags=["Alerts"])
async def acknowledge_alert(
    alert_id: int,
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.WRITE_ALERTS)),
):
    alert = db.execute_one(
        "SELECT id FROM alerts WHERE id = ? AND org_id = ?",
        (alert_id, org["id"]),
    )
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    db.execute_insert("UPDATE alerts SET sent = 1 WHERE id = ?", (alert_id,))
    return {"status": "acknowledged", "alert_id": alert_id}


@router.get("/reports/summary", response_model=ReportSummaryResponse, tags=["Reports"])
async def get_summary_report(
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.READ_DASHBOARD)),
):
    projects = orchestrator.list_projects(org_id=org["id"])
    total = len(projects)
    active = sum(1 for p in projects if p.get("status") == "active")
    failed = sum(1 for p in projects if p.get("status") == "failed")
    return {
        "total_projects": total,
        "active_projects": active,
        "failed_projects": failed,
        "success_rate": round(active / max(total, 1), 2),
    }


@router.get("/reports/project/{project_id}", response_model=ProjectReportResponse, tags=["Reports"])
async def get_project_report(
    project_id: str = Path(max_length=128),
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.READ_PROJECTS)),
):
    report = orchestrator.generate_project_report(project_id, org_id=org["id"])
    if not report:
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found")
    return report
