"""WebSocket event bridging from foreign threads (worker/scheduler → main loop)."""

import asyncio
import threading
from datetime import datetime, timezone

import pytest

from picosentry.serve.services.event_bus import Event
from picosentry.serve.services.websocket_manager import websocket_event_handler, ws_manager


def _event(event_type: str) -> Event:
    return Event(
        id="evt-1",
        type=event_type,
        source="orchestrator",
        payload={"run_id": "run-1"},
        timestamp=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_foreign_thread_event_reaches_broadcast(monkeypatch):
    monkeypatch.setattr(ws_manager, "main_loop", asyncio.get_running_loop())
    done = asyncio.Event()
    seen: list[tuple[str, dict]] = []

    async def fake_broadcast(event_type: str, payload: dict):
        seen.append((event_type, payload))
        done.set()

    monkeypatch.setattr(ws_manager, "broadcast", fake_broadcast)

    thread = threading.Thread(target=websocket_event_handler, args=(_event("project.run.started"),))
    thread.start()
    await asyncio.wait_for(done.wait(), timeout=5)
    thread.join()

    assert seen[0][0] == "project.run.started"
    assert seen[0][1]["payload"] == {"run_id": "run-1"}


def test_event_dropped_before_loop_captured(monkeypatch):
    seen: list[str] = []

    async def fake_broadcast(event_type: str, payload: dict):
        seen.append(event_type)

    monkeypatch.setattr(ws_manager, "broadcast", fake_broadcast)
    monkeypatch.setattr(ws_manager, "main_loop", None)

    websocket_event_handler(_event("project.run.failed"))

    assert seen == []
