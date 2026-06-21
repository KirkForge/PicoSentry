import logging

from fastapi import APIRouter, Depends, Query

from picosentry.serve.api.deps import require_role
from picosentry.serve.services.audit_cleanup import get_audit_stats, purge_audit_logs
from picosentry.serve.services.backup import BackupManager
from picosentry.serve.services.event_bus import event_bus
from picosentry.serve.services.log_manager import log_manager

logger = logging.getLogger("picoshogun.admin")

router = APIRouter()


@router.post("/backup", tags=["Backup"])
async def create_backup(user: dict = Depends(require_role("admin"))):
    backup_mgr = BackupManager()
    result = backup_mgr.create_backup()
    return {"status": "backup_created", "path": result}


@router.get("/backups", tags=["Backup"])
async def list_backups(user: dict = Depends(require_role("admin"))):
    backup_mgr = BackupManager()
    backups = backup_mgr.list_backups()
    return {"backups": backups}


@router.get("/logs/stats", tags=["Logs"])
async def get_log_stats(user: dict = Depends(require_role("admin"))):
    return log_manager.get_stats()


@router.post("/logs/rotate", tags=["Logs"])
async def rotate_logs(user: dict = Depends(require_role("admin"))):
    log_manager.rotate()
    return {"status": "rotated"}


@router.get("/logs", tags=["Logs"])
async def get_logs(
    level: str | None = None,
    source: str | None = None,
    search: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    user: dict = Depends(require_role("admin")),
):
    return {"entries": log_manager.query(level=level, source=source, search=search, limit=limit)}


@router.get("/audit/stats", tags=["Audit"])
async def audit_stats(user: dict = Depends(require_role("admin"))):
    return get_audit_stats()


@router.post("/audit/purge", tags=["Audit"])
async def purge_audit(
    retention_days: int | None = None,
    dry_run: bool = False,
    user: dict = Depends(require_role("admin")),
):
    return purge_audit_logs(retention_days=retention_days, dry_run=dry_run)


@router.get("/events/history", tags=["Events"])
async def get_event_history(
    event_type: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    user: dict = Depends(require_role("admin")),
):
    events = event_bus.get_history(event_type, limit)
    return [
        {
            "id": e.id,
            "type": e.type,
            "source": e.source,
            "payload": e.payload,
            "timestamp": e.timestamp.isoformat(),
            "priority": e.priority,
        }
        for e in events
    ]
