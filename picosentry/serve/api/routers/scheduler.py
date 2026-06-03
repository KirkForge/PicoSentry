"""Scheduler job management endpoints."""
import logging

from fastapi import APIRouter, Depends, HTTPException

from picosentry.serve.api.deps import get_current_user, require_role
from picosentry.serve.api.models import SchedulerJobCreateRequest
from picosentry.serve.services.scheduler import scheduler

logger = logging.getLogger("picoshogun.scheduler")

router = APIRouter(prefix="/scheduler")


@router.get("/jobs", tags=["Scheduler"])
async def list_scheduler_jobs(user: dict = Depends(get_current_user)):
    """List all scheduled jobs."""
    return {"jobs": scheduler.get_status()}


@router.post("/jobs", tags=["Scheduler"])
async def create_scheduler_job(
    request: SchedulerJobCreateRequest,
    user: dict = Depends(require_role("operator")),
):
    """Create a new scheduled job (operator+ required)."""
    try:
        job_id = scheduler.add_job(
            name=request.name,
            cron=request.cron,
            command=request.command,
            params=request.params,
            enabled=request.enabled,
        )
        return {"job_id": job_id, "status": "scheduled"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None


@router.patch("/jobs/{job_id}/enable", tags=["Scheduler"])
async def enable_scheduler_job(job_id: str, user: dict = Depends(require_role("operator"))):
    """Enable a scheduled job (operator+ required)."""
    scheduler.enable_job(int(job_id))
    return {"job_id": job_id, "status": "enabled"}


@router.patch("/jobs/{job_id}/disable", tags=["Scheduler"])
async def disable_scheduler_job(job_id: str, user: dict = Depends(require_role("operator"))):
    """Disable a scheduled job (operator+ required)."""
    scheduler.disable_job(int(job_id))
    return {"job_id": job_id, "status": "disabled"}


@router.delete("/jobs/{job_id}", tags=["Scheduler"], status_code=204)
async def delete_scheduler_job(job_id: str, user: dict = Depends(require_role("admin"))):
    """Delete a scheduled job (admin+ required)."""
    scheduler.remove_job(int(job_id))
