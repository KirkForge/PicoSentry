import logging

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

from picosentry.serve.api.deps import get_current_org, require_role
from picosentry.serve.api.models import (
    ChainListResponse,
    ChainNarrativeResponse,
    ChainsPersistResponse,
    ChainsSummaryResponse,
    EngineStatsResponse,
    EventIngestResponse,
)
from picosentry.serve.services.correlation import correlation_engine

logger = logging.getLogger("picoshogun.correlation")

router = APIRouter(tags=["Correlation"])


class EventIngestRequest(BaseModel):
    artifact_id: str = Field(..., max_length=512)
    layer: str = Field(..., pattern="^(scan|sandbox_l3|sandbox_l4|watch)$")
    rule_id: str = Field(..., max_length=128)
    severity: str = Field(default="MEDIUM", pattern="^(INFO|LOW|MEDIUM|HIGH|CRITICAL)$")
    confidence: str = Field(default="MEDIUM", pattern="^(LOW|MEDIUM|HIGH|EXACT)$")
    target: str = Field(default="", max_length=512)
    title: str = Field(default="", max_length=256)
    detail: str = Field(default="", max_length=4096)


@router.get("/chains", response_model=ChainListResponse)
def list_chains(
    threshold: float = Query(0.0, ge=0.0, le=1.0, description="Minimum chain_score filter"),
    limit: int = Query(50, ge=1, le=500),
    user: dict = Depends(require_role("viewer")),
    org: dict = Depends(get_current_org),
):
    if threshold > 0:
        chains = correlation_engine.critical_chains(threshold=threshold)
    else:
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


@router.get("/chains/{artifact_id:path}", response_model=ChainNarrativeResponse)
def get_chain(
    artifact_id: str = Path(max_length=512),
    user: dict = Depends(require_role("viewer")),
    org: dict = Depends(get_current_org),
):
    chain = correlation_engine.kill_chain(artifact_id)
    if chain is None:
        raise HTTPException(
            status_code=404,
            detail=f"No kill-chain data for artifact: {artifact_id}",
        )
    return chain.to_dict()


@router.get("/chains/{artifact_id:path}/narrative", response_model=ChainNarrativeResponse)
def get_chain_narrative(
    artifact_id: str = Path(max_length=512),
    user: dict = Depends(require_role("viewer")),
    org: dict = Depends(get_current_org),
):
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
        "phase_count": len(chain.phases),
        "event_count": sum(len(events) for events in chain.phases.values()),
    }


@router.post("/events", response_model=EventIngestResponse)
def ingest_event(
    body: EventIngestRequest,
    user: dict = Depends(require_role("operator")),
    org: dict = Depends(get_current_org),
):
    from datetime import datetime, timezone

    from picosentry._core.models import Confidence, Severity
    from picosentry.serve.services.correlation import CorrelatedEvent

    try:
        sev = Severity(body.severity.upper())
    except ValueError as err:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {body.severity}") from err

    try:
        conf = Confidence(body.confidence.upper())
    except ValueError as err:
        raise HTTPException(status_code=400, detail=f"Invalid confidence: {body.confidence}") from err

    event = CorrelatedEvent(
        artifact_id=body.artifact_id,
        layer=body.layer,
        rule_id=body.rule_id,
        severity=sev,
        confidence=conf,
        target=body.target or body.artifact_id,
        title=body.title or f"{body.layer}/{body.rule_id}",
        detail=body.detail,
        timestamp=datetime.now(timezone.utc).isoformat(),
        org_id=org["id"],
    )
    correlation_engine.ingest(event)

    return {"status": "ok", "event": event.to_dict()}


@router.get("/chains/summary", response_model=ChainsSummaryResponse)
def chains_summary(
    user: dict = Depends(require_role("viewer")),
    org: dict = Depends(get_current_org),
):
    return correlation_engine.chains_summary()


@router.post("/chains/persist", response_model=ChainsPersistResponse)
def persist_chains(
    user: dict = Depends(require_role("operator")),
    org: dict = Depends(get_current_org),
):
    event_count = correlation_engine.persist_events()
    chain_count = correlation_engine.persist_chains_cache()
    return {
        "status": "ok",
        "events_persisted": event_count,
        "chains_persisted": chain_count,
        "persist_enabled": correlation_engine.PERSIST_ENABLED,
    }


@router.get("/engine/stats", response_model=EngineStatsResponse)
def engine_stats(
    user: dict = Depends(require_role("viewer")),
    org: dict = Depends(get_current_org),
):
    return correlation_engine.stats()
