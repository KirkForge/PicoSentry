import logging

from fastapi import APIRouter, Depends

from picosentry.serve.api.deps import get_current_user
from picosentry.serve.services.plugin_manager import plugin_manager

logger = logging.getLogger("picoshogun.plugins")

router = APIRouter()


@router.get("/plugins", tags=["Plugins"])
async def list_plugins(user: dict = Depends(get_current_user)):
    return {"plugins": plugin_manager.get_status()}
