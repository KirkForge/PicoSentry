import logging

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

from picosentry.serve.api.deps import get_current_org, require_permission
from picosentry.serve.api.models import AnomalyAlertItem, AnomalyCheckResponse, AnomalyRuleResponse
from picosentry.serve.services.rbac import Permission


class AnomalyRuleUpdateRequest(BaseModel):
    enabled: bool | None = None
    threshold: float | None = Field(None, ge=0.0, le=1.0)


def _get_anomaly_detector():
    from picosentry.serve.api.server import anomaly_detector

    return anomaly_detector


logger = logging.getLogger("picoshogun.anomaly")

router = APIRouter(prefix="/anomaly")


@router.get("/rules", tags=["Anomaly"], response_model=list[AnomalyRuleResponse])
async def list_anomaly_rules(
    user: dict = Depends(require_permission(Permission.READ_ANOMALY)),
    org: dict = Depends(get_current_org),
):
    return _get_anomaly_detector().get_rules(org_id=str(org["id"]))


@router.get("/alerts", tags=["Anomaly"], response_model=list[AnomalyAlertItem])
async def list_anomaly_alerts(
    limit: int = Query(50, ge=1, le=200),
    user: dict = Depends(require_permission(Permission.READ_ANOMALY)),
    org: dict = Depends(get_current_org),
):
    return _get_anomaly_detector().get_alerts(limit=limit, org_id=str(org["id"]))


@router.post("/check", response_model=AnomalyCheckResponse, tags=["Anomaly"])
async def trigger_anomaly_check(
    user: dict = Depends(require_permission(Permission.WRITE_ANOMALY)),
    org: dict = Depends(get_current_org),
):
    detector = _get_anomaly_detector()
    alerts = detector.check_rules()
    return {
        "triggered": len(alerts),
        "alerts": [
            {
                "rule_id": a.rule_id,
                "metric": a.metric_name,
                "value": a.value,
                "threshold": a.threshold,
                "severity": a.severity,
            }
            for a in alerts
        ],
    }


@router.patch("/rules/{rule_id}", response_model=AnomalyRuleResponse, tags=["Anomaly"])
async def update_anomaly_rule(
    rule_id: Annotated[str, Path(max_length=64)],
    body: AnomalyRuleUpdateRequest,
    user: dict = Depends(require_permission(Permission.WRITE_ANOMALY)),
    org: dict = Depends(get_current_org),
):
    updates: dict = {}
    if body.enabled is not None:
        updates["enabled"] = body.enabled
    if body.threshold is not None:
        updates["threshold"] = body.threshold
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")
    detector = _get_anomaly_detector()
    if not detector.update_rule(rule_id, **updates):
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")
    matching = [r for r in detector.get_rules(org_id=str(org["id"])) if r["id"] == rule_id]
    if not matching:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found after update")
    return matching[0]
