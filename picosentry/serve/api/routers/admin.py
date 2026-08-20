import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from picosentry.serve.api.deps import get_current_org, require_role
from picosentry.serve.api.models import (
    AuditPurgeResponse,
    AuditStatsResponse,
    AuditVerifyResponse,
    BackupListResponse,
    BackupResponse,
    EventHistoryItem,
    LogQueryResponse,
    LogRotateResponse,
    LogStatsResponse,
)
from picosentry.serve.services.audit_chain import verify_audit_chain
from picosentry.serve.services.audit_cleanup import get_audit_stats, purge_audit_logs
from picosentry.serve.services.backup import BackupManager
from picosentry.serve.services.event_bus import event_bus
from picosentry.serve.services.log_manager import log_manager

logger = logging.getLogger("picoshogun.admin")

router = APIRouter()


@router.post("/backup", tags=["Backup"], response_model=BackupResponse)
async def create_backup(user: dict = Depends(require_role("admin")), org: dict = Depends(get_current_org)):
    backup_mgr = BackupManager()
    result = await asyncio.to_thread(backup_mgr.create_backup)
    if not result:
        raise HTTPException(status_code=500, detail="Backup failed")
    return {"status": "backup_created", "path": result["path"]}


@router.get("/backups", tags=["Backup"], response_model=BackupListResponse)
async def list_backups(user: dict = Depends(require_role("admin")), org: dict = Depends(get_current_org)):
    backup_mgr = BackupManager()
    backups = backup_mgr.list_backups()
    return {"backups": backups}


@router.get("/logs/stats", tags=["Logs"], response_model=LogStatsResponse)
async def get_log_stats(user: dict = Depends(require_role("admin")), org: dict = Depends(get_current_org)):
    return log_manager.get_stats()


@router.post("/logs/rotate", tags=["Logs"], response_model=LogRotateResponse)
async def rotate_logs(user: dict = Depends(require_role("admin")), org: dict = Depends(get_current_org)):
    log_manager.rotate()
    return {"status": "rotated"}


@router.get("/logs", tags=["Logs"], response_model=LogQueryResponse)
async def get_logs(
    level: str | None = Query(None, max_length=64),
    source: str | None = Query(None, max_length=128),
    search: str | None = Query(None, max_length=256),
    limit: int = Query(100, ge=1, le=1000),
    user: dict = Depends(require_role("admin")),
    org: dict = Depends(get_current_org),
):
    return {"entries": log_manager.query(level=level, source=source, search=search, limit=limit)}


@router.get("/audit/stats", tags=["Audit"], response_model=AuditStatsResponse)
async def audit_stats(user: dict = Depends(require_role("admin")), org: dict = Depends(get_current_org)):
    return get_audit_stats(org_id=org["id"])


@router.get("/audit/verify", tags=["Audit"], response_model=AuditVerifyResponse)
async def audit_verify(
    limit: int | None = Query(None, ge=1),
    user: dict = Depends(require_role("admin")),
    org: dict = Depends(get_current_org),
):
    from picosentry.serve.middleware.audit import writer_dropped_count
    from picosentry.serve.services.correlation import correlation_engine

    return {
        **verify_audit_chain(org_id=org["id"], limit=limit),
        "dropped_audit_records": writer_dropped_count(),
        "dropped_correlation_events": correlation_engine.dropped_events,
    }


@router.post("/audit/purge", tags=["Audit"], response_model=AuditPurgeResponse)
async def purge_audit(
    retention_days: int | None = Query(None, ge=1),
    dry_run: bool = Query(False),
    user: dict = Depends(require_role("admin")),
    org: dict = Depends(get_current_org),
):
    return purge_audit_logs(retention_days=retention_days, dry_run=dry_run, org_id=org["id"])


@router.get("/events/history", tags=["Events"], response_model=list[EventHistoryItem])
async def get_event_history(
    event_type: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    user: dict = Depends(require_role("admin")),
    org: dict = Depends(get_current_org),
):
    # org_id=None is a system-wide event: WS broadcasts it to every
    # authenticated socket (websocket_manager.broadcast), so the queryable
    # history surface must include it too — otherwise admins see scheduler
    # /backup events in their WS feed but cannot retrieve them after the
    # fact. Matches WS fan-out semantics. get_history(org_id=None) returns
    # the unfiltered history; we then keep this org's events + system events
    # only (cross-org isolation preserved).
    org_id = str(org["id"])
    events = event_bus.get_history(event_type, limit=1000, org_id=None)
    visible = [e for e in events if e.org_id is None or e.org_id == org_id]
    return [
        {
            "id": e.id,
            "type": e.type,
            "source": e.source,
            "payload": e.payload,
            "timestamp": e.timestamp.isoformat(),
            "priority": e.priority,
        }
        for e in visible[-limit:]
    ]
