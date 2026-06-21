import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from picosentry.serve.api.deps import require_permission
from picosentry.serve.services.rbac import Permission


def _get_anomaly_detector():
    from picosentry.serve.api.server import anomaly_detector

    return anomaly_detector


logger = logging.getLogger("picoshogun.anomaly")

router = APIRouter(prefix="/anomaly")


@router.get("/rules", tags=["Anomaly"])
async def list_anomaly_rules(user: dict = Depends(require_permission(Permission.READ_ANOMALY))):
    return _get_anomaly_detector().get_rules()


@router.get("/alerts", tags=["Anomaly"])
async def list_anomaly_alerts(
    limit: int = Query(50, ge=1, le=200),
    user: dict = Depends(require_permission(Permission.READ_ANOMALY)),
):
    return _get_anomaly_detector().get_alerts(limit=limit)


@router.post("/check", tags=["Anomaly"])
async def trigger_anomaly_check(
    user: dict = Depends(require_permission(Permission.READ_ANOMALY)),
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


@router.patch("/rules/{rule_id}", tags=["Anomaly"])
async def update_anomaly_rule(
    rule_id: str,
    enabled: bool | None = None,
    threshold: float | None = None,
    user: dict = Depends(require_permission(Permission.WRITE_ANOMALY)),
):
    updates: dict = {}
    if enabled is not None:
        updates["enabled"] = enabled
    if threshold is not None:
        updates["threshold"] = threshold
    if not updates:
        raise HTTPException(400, "No updates provided")
    if not _get_anomaly_detector().update_rule(rule_id, **updates):
        raise HTTPException(404, f"Rule '{rule_id}' not found")
    return {"status": "updated", "rule_id": rule_id}
