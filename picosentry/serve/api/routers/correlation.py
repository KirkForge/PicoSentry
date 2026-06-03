"""Kill-chain correlation API endpoints."""
import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from picosentry.serve.api.deps import get_current_user, require_role
from picosentry.serve.services.correlation import correlation_engine

logger = logging.getLogger("picoshogun.correlation")

router = APIRouter(tags=["Correlation"])


@router.get("/chains")
def list_chains(
    threshold: float = Query(0.0, ge=0.0, le=1.0, description="Minimum chain_score filter"),
    limit: int = Query(50, ge=1, le=500),
    user: dict = Depends(require_role("viewer")),
):
    """List all kill chains sorted by score descending.

    Returns active chains (artifacts with correlated events across layers).
    """
    if threshold > 0:
        chains = correlation_engine.critical_chains(threshold=threshold)
    else:
        # No threshold — return all artifacts with any events
        all_ids = correlation_engine.all_artifact_ids()
        chains = []
        for artifact_id in all_ids:
            chain = correlation_engine.kill_chain(artifact_id)
            if chain:
                chains.append(chain)
        chains.sort(key=lambda c: c.chain_score, reverse=True)

    result = [c.to_dict() for c in chains[:limit]]

    return {
        "total": len(result),
        "chains": result,
    }


@router.get("/chains/{artifact_id:path}")
def get_chain(
    artifact_id: str,
    user: dict = Depends(require_role("viewer")),
):
    """Get the full kill-chain timeline for one artifact."""
    chain = correlation_engine.kill_chain(artifact_id)
    if chain is None:
        raise HTTPException(
            status_code=404,
            detail=f"No kill-chain data for artifact: {artifact_id}",
        )
    return chain.to_dict()


@router.get("/chains/{artifact_id:path}/narrative")
def get_chain_narrative(
    artifact_id: str,
    user: dict = Depends(require_role("viewer")),
):
    """Get the kill-chain narrative text for one artifact."""
    chain = correlation_engine.kill_chain(artifact_id)
    if chain is None:
        raise HTTPException(
            status_code=404,
            detail=f"No kill-chain data for artifact: {artifact_id}",
        )
    return {
        "artifact_id": artifact_id,
        "narrative": chain.narrative,
        "chain_score": round(chain.chain_score, 3),
        "phase_count": chain.phase_count,
        "event_count": sum(len(events) for events in chain.phases.values()),
    }


@router.post("/events")
def ingest_event(
    artifact_id: str = Query(..., description="Package@version identifier"),
    layer: str = Query(..., description="Source layer (scan|sandbox_l3|sandbox_l4|watch)"),
    rule_id: str = Query(..., description="Detector rule ID"),
    severity: str = Query("MEDIUM", description="Event severity"),
    confidence: str = Query("MEDIUM", description="Event confidence"),
    target: str = Query("", description="Scan target / project name"),
    title: str = Query("", description="Human-readable title"),
    detail: str = Query("", description="Evidence / context"),
    user: dict = Depends(require_role("operator")),
):
    """Ingest a custom correlated event (for external integrations)."""
    from datetime import datetime, timezone

    from picosentry._core.models import Confidence, Severity
    from picosentry.serve.services.correlation import CorrelatedEvent

    # Parse enums
    try:
        sev = Severity(severity.upper())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")

    try:
        conf = Confidence(confidence.upper())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid confidence: {confidence}")

    valid_layers = {"scan", "sandbox_l3", "sandbox_l4", "watch"}
    if layer not in valid_layers:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid layer: {layer}. Must be one of: {', '.join(sorted(valid_layers))}",
        )

    event = CorrelatedEvent(
        artifact_id=artifact_id,
        layer=layer,
        rule_id=rule_id,
        severity=sev,
        confidence=conf,
        target=target or artifact_id,
        title=title or f"{layer}/{rule_id}",
        detail=detail,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    correlation_engine.ingest(event)

    return {"status": "ok", "event": event.to_dict()}


@router.get("/chains/summary")
def chains_summary(
    user: dict = Depends(require_role("viewer")),
):
    """Get kill chains dashboard summary.

    Returns aggregate metrics: total/critical/high/medium/low counts,
    layer coverage, phase distribution, and top 10 chains.
    """
    return correlation_engine.chains_summary()


@router.post("/chains/persist")
def persist_chains(
    user: dict = Depends(require_role("operator")),
):
    """Persist in-memory events and chains to SQLite (if enabled)."""
    event_count = correlation_engine.persist_events()
    chain_count = correlation_engine.persist_chains_cache()
    return {
        "status": "ok",
        "events_persisted": event_count,
        "chains_persisted": chain_count,
        "persist_enabled": correlation_engine.PERSIST_ENABLED,
    }


@router.get("/engine/stats")
def engine_stats(
    user: dict = Depends(require_role("viewer")),
):
    """Get correlation engine statistics."""
    return correlation_engine.stats()