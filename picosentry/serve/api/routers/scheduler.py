import logging

from fastapi import APIRouter, Depends, HTTPException

from picosentry.serve.api.deps import get_current_org, require_permission
from picosentry.serve.api.models import (
    SchedulerJobCreateRequest,
    SchedulerJobListResponse,
    SchedulerJobResponse,
    SchedulerJobStatusResponse,
    SchedulerJobUpdateRequest,
)
from picosentry.serve.services.rbac import Permission
from picosentry.serve.services.scheduler import SchedulerJobConflict, scheduler

logger = logging.getLogger("picoshogun.scheduler")

router = APIRouter(prefix="/scheduler")


@router.get("/jobs", response_model=SchedulerJobListResponse, tags=["Scheduler"])
async def list_scheduler_jobs(
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.READ_SCHEDULER)),
):
    org_id = org["id"]
    return {"jobs": [j for j in scheduler.get_status() if j.get("org_id") == org_id]}


@router.post("/jobs", tags=["Scheduler"], status_code=201, response_model=SchedulerJobResponse)
async def create_scheduler_job(
    request: SchedulerJobCreateRequest,
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.WRITE_SCHEDULER)),
):
    try:
        job_id = scheduler.add_job(
            name=request.name,
            cron=request.cron,
            command=request.command,
            params=(
                request.params.model_dump(exclude_none=True)
                if hasattr(request.params, "model_dump")
                else {k: v for k, v in request.params.dict().items() if v is not None}
            )
            if request.params
            else None,
            enabled=request.enabled,
            org_id=org["id"],
        )
        return {"job_id": job_id, "status": "scheduled"}
    except SchedulerJobConflict as e:
        raise HTTPException(status_code=409, detail=str(e)) from None
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None


@router.patch("/jobs/{job_id}/enable", response_model=SchedulerJobStatusResponse, tags=["Scheduler"])
async def enable_scheduler_job(
    job_id: int,
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.WRITE_SCHEDULER)),
):
    _assert_job_in_org(job_id, org["id"])
    scheduler.enable_job(job_id)
    return {"job_id": job_id, "status": "enabled"}


@router.patch("/jobs/{job_id}/disable", response_model=SchedulerJobStatusResponse, tags=["Scheduler"])
async def disable_scheduler_job(
    job_id: int,
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.WRITE_SCHEDULER)),
):
    _assert_job_in_org(job_id, org["id"])
    scheduler.disable_job(job_id)
    return {"job_id": job_id, "status": "disabled"}


@router.patch("/jobs/{job_id}", response_model=SchedulerJobStatusResponse, tags=["Scheduler"])
async def update_scheduler_job(
    job_id: int,
    request: SchedulerJobUpdateRequest,
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.WRITE_SCHEDULER)),
):
    _assert_job_in_org(job_id, org["id"])
    try:
        updated = scheduler.update_job(
            job_id,
            cron=request.cron,
            params=(
                request.params.model_dump(exclude_none=True)
                if hasattr(request.params, "model_dump")
                else {k: v for k, v in request.params.dict().items() if v is not None}
            )
            if request.params
            else None,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
    if not updated:
        raise HTTPException(status_code=404, detail="Scheduler job not found")
    return {"job_id": job_id, "status": "updated"}


@router.post("/jobs/{job_id}/run", response_model=SchedulerJobStatusResponse, tags=["Scheduler"])
async def trigger_scheduler_job(
    job_id: int,
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.WRITE_SCHEDULER)),
):
    _assert_job_in_org(job_id, org["id"])
    if not scheduler.trigger_job(job_id):
        raise HTTPException(status_code=409, detail="Job not found or disabled")
    return {"job_id": job_id, "status": "triggered"}


@router.delete("/jobs/{job_id}", tags=["Scheduler"], status_code=204)
async def delete_scheduler_job(
    job_id: int,
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.WRITE_SCHEDULER)),
):
    _assert_job_in_org(job_id, org["id"])
    scheduler.remove_job(job_id)


def _assert_job_in_org(job_id: int, org_id: int) -> None:
    job = scheduler.jobs.get(job_id)
    if job is None or job.org_id != org_id:
        raise HTTPException(status_code=404, detail="Scheduler job not found")
