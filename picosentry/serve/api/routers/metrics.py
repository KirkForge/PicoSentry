"""Metrics and observability endpoints."""
import logging

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse

from picosentry.serve.api.deps import get_current_user
from picosentry.serve.services.metrics import metrics

logger = logging.getLogger("picoshogun.metrics")

router = APIRouter()


@router.get("/metrics", tags=["Metrics"])
async def get_metrics(
    format: str = Query("json", pattern="^(json|prometheus)$"),
    user: dict = Depends(get_current_user),
):
    """Get system metrics in JSON or Prometheus format."""
    if format == "prometheus":
        return PlainTextResponse(content=metrics.to_prometheus(), media_type="text/plain")
    return metrics.to_dict()


@router.get("/metrics/prometheus", tags=["Metrics"])
async def get_prometheus_metrics():
    """Prometheus text-based metrics endpoint (no auth for scrape compatibility)."""
    return PlainTextResponse(content=metrics.to_prometheus(), media_type="text/plain")


@router.get("/metrics/json", tags=["Metrics"])
async def get_json_metrics(user: dict = Depends(get_current_user)):
    """JSON metrics endpoint."""
    return metrics.to_dict()
