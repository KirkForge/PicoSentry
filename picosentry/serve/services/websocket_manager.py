import asyncio
import json
import logging
import re
from datetime import datetime, timezone

from fastapi import WebSocket

from picosentry.serve.services.event_bus import Event, event_bus

logger = logging.getLogger("picoshogun.WS")

MAX_CHANNELS = 16
_CHANNEL_NAME_RE = re.compile(r"^[a-zA-Z0-9_.:-]{1,64}$")


def _normalize_org_id(org_id) -> str | None:
    return str(org_id) if org_id is not None else None


def validate_channels(channels: list[str]) -> list[str]:
    """Cap the subscribe list at MAX_CHANNELS and validate each name."""
    if len(channels) > MAX_CHANNELS:
        raise ValueError(f"Too many channels requested (max {MAX_CHANNELS})")
    for channel in channels:
        if channel != "*" and not _CHANNEL_NAME_RE.match(channel):
            raise ValueError(f"Invalid channel name: {channel!r}")
    return channels


class ConnectionManager:
    # Per-consumer outbound queue bound. A slow consumer's queue fills and
    # NEW messages are dropped (audit-writer pattern) instead of letting
    # one stalled send head-of-line-block every other client.
    OUTBOUND_QUEUE_SIZE = 256

    def __init__(self):
        self.connections: dict[str, set[WebSocket]] = {}
        self.client_channels: dict[WebSocket, set[str]] = {}
        self.client_orgs: dict[WebSocket, str | None] = {}
        self._lock = asyncio.Lock()
        self.main_loop: asyncio.AbstractEventLoop | None = None
        self._outbound: dict[WebSocket, asyncio.Queue[str]] = {}
        self._pumps: dict[WebSocket, asyncio.Task] = {}
        self.dropped = 0

    def _dropped(self) -> None:
        from picosentry.serve.services.metrics import metrics

        self.dropped += 1
        metrics.set_global_gauge("ws_dropped_messages", self.dropped)
        logger.warning("WS outbound queue full — dropping message (dropped so far: %d)", self.dropped)

    async def _pump(self, websocket: WebSocket, queue: asyncio.Queue[str]) -> None:
        """Serial sender owned by ONE consumer; broadcast() never awaits sends."""
        while True:
            message = await queue.get()
            try:
                await websocket.send_text(message)
            except Exception:
                # Client is gone or the send failed; the receive loop in the
                # ws router will notice and call disconnect(), which cancels
                # this pump. Stop draining for a dead socket.
                return

    def _enqueue(self, websocket: WebSocket, message: str) -> None:
        queue = self._outbound.get(websocket)
        task = self._pumps.get(websocket)
        if queue is None or task is None or task.done():
            queue = asyncio.Queue(maxsize=self.OUTBOUND_QUEUE_SIZE)
            self._outbound[websocket] = queue
            self._pumps[websocket] = asyncio.create_task(self._pump(websocket, queue))
        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:
            self._dropped()

    async def connect(self, websocket: WebSocket, channels: list[str] | None = None, org_id=None):
        await websocket.accept()
        channels_set: set[str] = set(channels) if channels is not None else {"*"}
        async with self._lock:
            self.client_orgs[websocket] = _normalize_org_id(org_id)
            self._add_sub(websocket, channels_set)

    async def set_org(self, websocket: WebSocket, org_id):
        async with self._lock:
            self.client_orgs[websocket] = _normalize_org_id(org_id)

    def _add_sub(self, websocket: WebSocket, channels: set):
        self.client_channels[websocket] = channels
        for channel in channels:
            if channel not in self.connections:
                self.connections[channel] = set()
            self.connections[channel].add(websocket)

    async def subscribe(self, websocket: WebSocket, channels: list):
        channels = validate_channels(list(channels or ["*"]))
        async with self._lock:
            if websocket in self.client_channels:
                for ch in self.client_channels[websocket]:
                    self._remove_from_channel(websocket, ch)
            self._add_sub(websocket, set(channels))

    def _remove_from_channel(self, websocket: WebSocket, channel: str):
        if channel in self.connections:
            self.connections[channel].discard(websocket)
            if not self.connections[channel]:
                del self.connections[channel]

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.client_channels:
                for channel in self.client_channels[websocket]:
                    self._remove_from_channel(websocket, channel)
                del self.client_channels[websocket]
            self.client_orgs.pop(websocket, None)
            self._outbound.pop(websocket, None)
            pump = self._pumps.pop(websocket, None)
            if pump is not None:
                pump.cancel()

    async def broadcast(self, event_type: str, payload: dict, org_id=None):
        org = _normalize_org_id(org_id)
        message = json.dumps(
            {
                "type": event_type,
                "payload": payload,
                "org_id": org,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        async with self._lock:
            candidates = {*self.connections.get("*", set()), *self.connections.get(event_type, set())}
            # org_id=None is a system-wide event: visible to every authenticated
            # socket.  Org-stamped events fan out only to that org's sockets.
            if org is not None:
                candidates = {ws for ws in candidates if self.client_orgs.get(ws) == org}
            else:
                candidates = {ws for ws in candidates if ws in self.client_channels}

        # Non-blocking per-consumer enqueue: one slow client's full queue
        # drops its own messages, never delays another client's delivery.
        for ws in candidates:
            self._enqueue(ws, message)


ws_manager = ConnectionManager()


def websocket_event_handler(event: Event):
    payload = {
        "source": event.source,
        "payload": event.payload,
        "priority": event.priority,
        "org_id": event.org_id,
    }
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        main_loop = ws_manager.main_loop
        if main_loop is None:
            logger.warning("Dropping WebSocket event %s: main loop not captured yet", event.type)
            return
        logger.debug("Bridging WebSocket event %s from foreign thread onto main loop", event.type)
        loop = main_loop
    loop.call_soon_threadsafe(lambda: loop.create_task(ws_manager.broadcast(event.type, payload, org_id=event.org_id)))


event_bus.subscribe("*", websocket_event_handler)
