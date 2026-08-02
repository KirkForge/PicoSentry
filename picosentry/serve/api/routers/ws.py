import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from picosentry.serve.api.deps import auth_service
from picosentry.serve.services.websocket_manager import ws_manager

logger = logging.getLogger("picoshogun.ws")

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token") or websocket.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        await websocket.close(code=4001, reason="Unauthorized")
        return
    user = auth_service.validate_token(token)
    if not user:
        await websocket.close(code=4001, reason="Invalid authentication token")
        return
    await websocket.accept()
    await ws_manager.connect(websocket, channels=[])
    await websocket.send_text(
        json.dumps(
            {
                "type": "auth",
                "status": "ok",
                "user_id": user.get("user_id"),
                "note": 'send {"action": "subscribe", "channels": [...]} to receive events',
            }
        )
    )
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                logger.debug("ws: ignoring non-JSON frame from %s", websocket.client)
                continue

            action = msg.get("action")

            if action == "subscribe":
                channels = msg.get("channels") or ["*"]
                await ws_manager.subscribe(websocket, channels)
                await websocket.send_text(json.dumps({"type": "subscribed", "channels": channels}))
            elif action == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
