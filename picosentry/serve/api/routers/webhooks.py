import logging

from fastapi import APIRouter, Depends, HTTPException

from picosentry.serve.api.deps import get_current_user, require_role
from picosentry.serve.api.models import WebhookCreateRequest
from picosentry.serve.services.webhooks import webhook_manager

logger = logging.getLogger("picoshogun.webhooks")

router = APIRouter()


@router.get("/webhooks", tags=["Webhooks"])
async def list_webhooks(user: dict = Depends(get_current_user)):
    return {
        "webhooks": {
            name: {"url": w.url, "events": w.events, "active": w.active} for name, w in webhook_manager.webhooks.items()
        }
    }


@router.post("/webhooks", tags=["Webhooks"])
async def create_webhook(
    request: WebhookCreateRequest,
    user: dict = Depends(require_role("operator")),
):
    try:
        webhook_id = webhook_manager.create(
            name=request.name,
            url=request.url,
            events=request.events,
            secret=request.secret,
        )
        return {"id": webhook_id, "url": request.url, "events": request.events}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
