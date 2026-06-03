"""Real-time WebSocket events for live monitoring."""
import asyncio
import contextlib
import json
from datetime import datetime

from fastapi import WebSocket

from picosentry.serve.services.event_bus import Event, event_bus


class ConnectionManager:
    """Manage WebSocket connections with channel-based subscriptions."""

    def __init__(self):
        self.connections: dict[str, set[WebSocket]] = {}
        self.client_channels: dict[WebSocket, set[str]] = {}

    async def connect(self, websocket: WebSocket, channels: list[str] | None = None):
        await websocket.accept()
        channels_set: set[str] = set(channels) if channels else {"*"}
        self._add_sub(websocket, channels_set)

    def _add_sub(self, websocket: WebSocket, channels: set):
        self.client_channels[websocket] = channels
        for channel in channels:
            if channel not in self.connections:
                self.connections[channel] = set()
            self.connections[channel].add(websocket)

    def subscribe(self, websocket: WebSocket, channels: list):
        """Update subscription channels without re-accepting."""
        # Remove from old channels
        if websocket in self.client_channels:
            for ch in self.client_channels[websocket]:
                self.connections[ch].discard(websocket)
        self._add_sub(websocket, set(channels or ["*"]))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.client_channels:
            for channel in self.client_channels[websocket]:
                if channel in self.connections:
                    self.connections[channel].discard(websocket)
            del self.client_channels[websocket]

    async def broadcast(self, event_type: str, payload: dict):
        """Broadcast event to all clients subscribed to matching channels."""
        message = json.dumps({
            "type": event_type,
            "payload": payload,
            "timestamp": datetime.now().isoformat()
        })

        # Send to wildcard subscribers
        for ws in self.connections.get("*", set()).copy():
            with contextlib.suppress(Exception):
                await ws.send_text(message)

        # Send to specific channel subscribers
        for ws in self.connections.get(event_type, set()).copy():
            with contextlib.suppress(Exception):
                await ws.send_text(message)

ws_manager = ConnectionManager()

def websocket_event_handler(event: Event):
    """Bridge event bus to WebSocket clients — thread-safe.

    Uses call_soon_threadsafe to safely schedule broadcasts from any thread.
    Falls back gracefully when no event loop is available.
    """
    payload = {
        "source": event.source,
        "payload": event.payload,
        "priority": event.priority,
    }
    try:
        loop = asyncio.get_running_loop()
        loop.call_soon_threadsafe(
            lambda: loop.create_task(ws_manager.broadcast(event.type, payload))
        )
    except RuntimeError:
        # No running event loop — skip WebSocket broadcast
        # (e.g. during startup or when called from sync code)
        pass

# Auto-subscribe event bus to WebSocket
event_bus.subscribe("*", websocket_event_handler)
