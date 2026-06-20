import logging

from fastapi import APIRouter, Depends, HTTPException

from picosentry.serve.api.deps import get_current_org, require_permission
from picosentry.serve.api.models import WebhookCreateRequest
from picosentry.serve.services.rbac import Permission
from picosentry.serve.services.webhooks import webhook_manager

logger = logging.getLogger("picoshogun.webhooks")

router = APIRouter()


@router.get("/webhooks", tags=["Webhooks"])
async def list_webhooks(
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.READ_WEBHOOKS)),
):
    org_id = org["id"]
    return {
        "webhooks": {
            name: {"url": w.url, "events": w.events, "active": w.active}
            for name, w in webhook_manager.webhooks.items()
            if w.org_id == org_id
        }
    }


@router.post("/webhooks", tags=["Webhooks"])
async def create_webhook(
    request: WebhookCreateRequest,
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.WRITE_WEBHOOKS)),
):
    try:
        webhook_id = webhook_manager.create(
            name=request.name,
            url=request.url,
            events=request.events,
            secret=request.secret,
            org_id=org["id"],
        )
        return {"id": webhook_id, "url": request.url, "events": request.events}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
