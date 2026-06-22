import logging

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse

from picosentry.serve.api.deps import get_current_org, require_permission
from picosentry.serve.services.metrics import metrics
from picosentry.serve.services.rbac import Permission

logger = logging.getLogger("picoshogun.metrics")

router = APIRouter()


@router.get("/metrics", tags=["Metrics"])
async def get_metrics(
    format: str = Query("json", pattern="^(json|prometheus)$"),
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.READ_METRICS)),
):
    if format == "prometheus":
        return PlainTextResponse(content=metrics.to_prometheus(org_id=org["id"]), media_type="text/plain")
    return metrics.to_dict(org_id=org["id"])


@router.get("/metrics/prometheus", tags=["Metrics"])
async def get_prometheus_metrics(
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.READ_METRICS)),
):
    return PlainTextResponse(content=metrics.to_prometheus(org_id=org["id"]), media_type="text/plain")


@router.get("/metrics/json", tags=["Metrics"])
async def get_json_metrics(
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.READ_METRICS)),
):
    return metrics.to_dict(org_id=org["id"])
