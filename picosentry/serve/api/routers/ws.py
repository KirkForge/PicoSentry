import asyncio
import json
import logging
import os

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from picosentry.serve.api.deps import auth_service
from picosentry.serve.services.orgs import Organization
from picosentry.serve.services.websocket_manager import ws_manager

logger = logging.getLogger("picoshogun.ws")


router = APIRouter()


def _resolve_org_id_sync(user: dict) -> int | None:
    """First org the user belongs to — same resolution get_current_org uses.

    Sync (blocking DB read); callers in the async websocket handler must
    dispatch via asyncio.to_thread to avoid blocking the event loop
    (WO6.0.0-020: sync DB reads on the loop).
    """
    try:
        user_orgs = Organization.list_orgs_for_user(user["id"])
    except (KeyError, OSError, ValueError, RuntimeError, TypeError):
        return None
    return user_orgs[0]["id"] if user_orgs else None


async def _resolve_org_id(user: dict) -> int | None:
    """Async wrapper: dispatches the blocking DB read to the threadpool."""
    return await asyncio.to_thread(_resolve_org_id_sync, user)


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str | None = None):
    """Authenticated WebSocket fanout.

    Connect-time contract (post P0 fix):
      * The server NEVER adds an unauthenticated client to the
        broadcast list.  ``ws_manager.connect`` is called with an empty
        channel set so the receive loop drains, but no event ever
        reaches the client until they ``subscribe`` to specific channels.
      * Auth can happen two ways:
          - query string ``?token=<jwt>`` at connect time — **development
            only**; in production, use the in-band auth message to avoid
            leaking credentials into proxy logs and browser history.
          - in-band ``{"action": "auth", "token": "<jwt>"}`` after connect.
        In both cases the client must still send ``subscribe`` to opt
        into broadcasts.  Authentication alone does not grant broadcast
        access.
      * A client that connects without a valid token and never sends an
        in-band ``auth`` is connected with an empty channel set.  They
        can talk (the receive loop still runs), but they receive no
        events and ``subscribe`` is rejected until they authenticate.
    """
    # Query-string tokens leak into proxy logs and browser history.
    # Only allow them in non-production environments.
    if token and os.environ.get("PICOSHOGUN_ENV", "production") == "production":
        await websocket.accept()
        await websocket.close(code=4001, reason="Query-string auth not allowed in production; use in-band auth")
        return

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
    org_id = await _resolve_org_id(user) if user else None
    await ws_manager.connect(websocket, channels=[], org_id=org_id)
    authenticated = user is not None

    if authenticated and user is not None:
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

            if action == "auth" and not authenticated:
                auth_token = msg.get("token", "")
                user = auth_service.validate_token(auth_token)
                if user:
                    authenticated = True
                    await ws_manager.set_org(websocket, await _resolve_org_id(user))
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
                try:
                    await ws_manager.subscribe(websocket, channels)
                except ValueError as exc:
                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "error",
                                "message": str(exc),
                            }
                        )
                    )
                    continue
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

    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception:
        logger.exception("Unexpected error in WebSocket handler")
        await ws_manager.disconnect(websocket)
