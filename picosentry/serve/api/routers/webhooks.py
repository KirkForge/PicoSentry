import logging

from fastapi import APIRouter, Depends, HTTPException

from picosentry.serve.api.deps import get_current_org, require_permission
from picosentry.serve.api.models import WebhookCreateRequest, WebhookListResponse, WebhookResponse
from picosentry.serve.services.rbac import Permission
from picosentry.serve.services.webhooks import WebhookNameConflict, webhook_manager

logger = logging.getLogger("picoshogun.webhooks")

router = APIRouter()


@router.get("/webhooks", response_model=WebhookListResponse, tags=["Webhooks"])
async def list_webhooks(
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.READ_WEBHOOKS)),
):
    org_id = org["id"]
    return {
        "webhooks": {
            w.name: {"url": w.url, "events": w.events, "active": w.active}
            for w in webhook_manager.webhooks.values()
            if w.org_id == org_id
        }
    }


@router.post("/webhooks", tags=["Webhooks"], status_code=201, response_model=WebhookResponse)
async def create_webhook(
    request: WebhookCreateRequest,
    org: dict = Depends(get_current_org),
    user: dict = Depends(require_permission(Permission.WRITE_WEBHOOKS)),
):
    if not request.url.startswith("https://"):
        raise HTTPException(status_code=400, detail="Webhook URL must use HTTPS")
    try:
        webhook_id = webhook_manager.create(
            name=request.name,
            url=request.url,
            events=request.events,
            secret=request.secret,
            org_id=org["id"],
        )
        return {"id": webhook_id, "url": request.url, "events": request.events}
    except WebhookNameConflict as e:
        raise HTTPException(status_code=409, detail=str(e)) from None
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
