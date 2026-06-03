"""Anomaly detection and rules management endpoints."""
import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from picosentry.serve.api.deps import get_current_user

# Lazy import to avoid circular dependency — anomaly_detector is created in server.py
def _get_anomaly_detector():
    from picosentry.serve.api.server import anomaly_detector
    return anomaly_detector

logger = logging.getLogger("picoshogun.anomaly")

router = APIRouter(prefix="/anomaly")


@router.get("/rules", tags=["Anomaly"])
async def list_anomaly_rules(user: dict = Depends(get_current_user)):
    """List all configured anomaly detection rules."""
    return _get_anomaly_detector().get_rules()


@router.get("/alerts", tags=["Anomaly"])
async def list_anomaly_alerts(limit: int = Query(50, ge=1, le=200), user: dict = Depends(get_current_user)):
    """List recent anomaly alerts."""
    return _get_anomaly_detector().get_alerts(limit=limit)


@router.post("/check", tags=["Anomaly"])
async def trigger_anomaly_check(user: dict = Depends(get_current_user)):
    """Manually trigger an anomaly detection cycle."""
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
async def update_anomaly_rule(rule_id: str, enabled: bool | None = None, threshold: float | None = None, user: dict = Depends(get_current_user)):
    """Update an anomaly detection rule (enable/disable or change threshold)."""
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
