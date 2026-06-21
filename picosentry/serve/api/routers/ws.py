import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from picosentry.serve.api.deps import auth_service
from picosentry.serve.services.websocket_manager import ws_manager

logger = logging.getLogger("picoshogun.ws")

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str | None = None):
    """Authenticated WebSocket fanout.

    Connect-time contract (post P0 fix):
      * The server NEVER adds an unauthenticated client to the
        broadcast list.  ``ws_manager.connect`` is called with an empty
        channel set so the receive loop drains, but no event ever
        reaches the client until they ``subscribe`` to specific channels.
      * Auth can happen two ways:
          - query string ``?token=<jwt>`` at connect time, or
          - in-band ``{"action": "auth", "token": "<jwt>"}`` after connect.
        In both cases the client must still send ``subscribe`` to opt
        into broadcasts.  Authentication alone does not grant broadcast
        access.
      * A client that connects without a valid token and never sends an
        in-band ``auth`` is connected with an empty channel set.  They
        can talk (the receive loop still runs), but they receive no
        events and ``subscribe`` is rejected until they authenticate.

    This is a deliberate tightening from the previous behaviour, which
    added every connect to ``channels=["*"]`` and therefore started
    streaming broadcasts the instant the TCP handshake completed.
    """
    user = None
    if token:
        user = auth_service.validate_token(token)
        if not user:
            # Reject early.  Accept+close is the standard pattern for
            # sending a non-1000 close code at the application layer.
            await websocket.accept()
            await websocket.close(code=4001, reason="Invalid authentication token")
            return

    # Empty channel set on connect — clients MUST opt in via subscribe
    # after authenticating.  See docstring above.
    await ws_manager.connect(websocket, channels=[])
    authenticated = user is not None

    if authenticated and user is not None:
        await websocket.send_text(
            json.dumps(
                {
                    "type": "auth",
                    "status": "ok",
                    "user_id": user.get("user_id"),
                    "note": 'connected; send {"action": "subscribe", "channels": [...] } to receive events',
                }
            )
        )

    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                # Malformed payload — ignore rather than disconnect; a
                # broken client shouldn't take out the room.
                logger.debug("ws: ignoring non-JSON frame from %s", websocket.client)
                continue

            action = msg.get("action")

            if action == "auth" and not authenticated:
                auth_token = msg.get("token", "")
                user = auth_service.validate_token(auth_token)
                if user:
                    authenticated = True
                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "auth",
                                "status": "ok",
                                "user_id": user.get("user_id"),
                            }
                        )
                    )
                else:
                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "auth",
                                "status": "denied",
                            }
                        )
                    )
                    # Close the connection on bad in-band auth.  The
                    # client is clearly trying to authenticate and
                    # failed; leaving the connection open with a stale
                    # unauthenticated state invites further probing.
                    await websocket.close(code=4001, reason="Invalid authentication token")
                    return

            elif action == "subscribe" and authenticated:
                channels = msg.get("channels") or ["*"]
                ws_manager.subscribe(websocket, channels)
                await websocket.send_text(
                    json.dumps(
                        {
                            "type": "subscribed",
                            "channels": channels,
                        }
                    )
                )

            elif action == "subscribe" and not authenticated:
                await websocket.send_text(
                    json.dumps(
                        {
                            "type": "error",
                            "message": "Authentication required before subscribe",
                        }
                    )
                )

            elif action == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))

            # Unknown actions are ignored, not echoed.  Keeps the
            # protocol surface narrow for a misuse to land on.
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
