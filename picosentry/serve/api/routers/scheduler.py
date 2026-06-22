import logging

from fastapi import APIRouter, Depends, HTTPException

from picosentry.serve.api.deps import get_current_org, require_permission
from picosentry.serve.api.models import SchedulerJobCreateRequest
from picosentry.serve.services.rbac import Permission
from picosentry.serve.services.scheduler import scheduler

logger = logging.getLogger("picoshogun.scheduler")

router = APIRouter(prefix="/scheduler")


@router.get("/jobs", tags=["Scheduler"])
async def list_scheduler_jobs(
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.READ_SCHEDULER)),
):
    org_id = org["id"]
    return {"jobs": [j for j in scheduler.get_status() if j.get("org_id") == org_id]}


@router.post("/jobs", tags=["Scheduler"])
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
            params=request.params,
            enabled=request.enabled,
            org_id=org["id"],
        )
        return {"job_id": job_id, "status": "scheduled"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None


@router.patch("/jobs/{job_id}/enable", tags=["Scheduler"])
async def enable_scheduler_job(
    job_id: str,
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.WRITE_SCHEDULER)),
):
    _assert_job_in_org(int(job_id), org["id"])
    scheduler.enable_job(int(job_id))
    return {"job_id": job_id, "status": "enabled"}


@router.patch("/jobs/{job_id}/disable", tags=["Scheduler"])
async def disable_scheduler_job(
    job_id: str,
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.WRITE_SCHEDULER)),
):
    _assert_job_in_org(int(job_id), org["id"])
    scheduler.disable_job(int(job_id))
    return {"job_id": job_id, "status": "disabled"}


@router.delete("/jobs/{job_id}", tags=["Scheduler"], status_code=204)
async def delete_scheduler_job(
    job_id: str,
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.WRITE_SCHEDULER)),
):
    _assert_job_in_org(int(job_id), org["id"])
    scheduler.remove_job(int(job_id))


def _assert_job_in_org(job_id: int, org_id: int) -> None:
    job = scheduler.jobs.get(job_id)
    if job is None or job.org_id != org_id:
        raise HTTPException(status_code=404, detail="Scheduler job not found")
