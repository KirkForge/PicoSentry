"""WebSocket endpoint for real-time event streaming."""
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from picosentry.serve.api.deps import auth_service
from picosentry.serve.services.websocket_manager import ws_manager

logger = logging.getLogger("picoshogun.ws")

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str | None = None):
    """Real-time WebSocket for live events with optional token auth.

    Clients can authenticate by:
    1. Passing ?token=<jwt> in the WebSocket URL
    2. Sending {"action": "auth", "token": "<jwt>"} after connecting
    """
    user = None
    if token:
        user = auth_service.validate_token(token)
        if not user:
            await websocket.close(code=4001, reason="Invalid authentication token")
            return

    await ws_manager.connect(websocket, channels=["*"])
    authenticated = user is not None

    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "auth" and not authenticated:
                    auth_token = msg.get("token", "")
                    user = auth_service.validate_token(auth_token)
                    if user:
                        authenticated = True
                        await websocket.send_text(json.dumps({"type": "auth", "status": "ok", "user_id": user.get("user_id")}))
                    else:
                        await websocket.send_text(json.dumps({"type": "auth", "status": "denied"}))
                        await websocket.close(code=4001, reason="Invalid authentication token")
                        return
                elif msg.get("action") == "subscribe" and authenticated:
                    channels = msg.get("channels", ["*"])
                    ws_manager.subscribe(websocket, channels)
                elif msg.get("action") == "subscribe" and not authenticated:
                    await websocket.send_text(json.dumps({"type": "error", "message": "Authentication required"}))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
