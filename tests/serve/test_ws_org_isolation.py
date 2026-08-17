"""Cross-tenant WebSocket event isolation (B1) + subscribe hardening (B8).

Pins the org-scoped fanout contract:

  1. An org-stamped event reaches only that org's authenticated sockets.
  2. A system-wide event (org_id=None) reaches every authenticated socket.
  3. Subscribe channel lists are capped at 16 and names validated —
     oversized or malformed lists get an error frame, no subscription.
  4. disconnect() removes empty channel sets.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from picosentry.serve.api.server import app
from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.services.websocket_manager import ConnectionManager, validate_channels, ws_manager


@pytest.fixture(scope="module", autouse=True)
def _isolated_ws_db(tmp_path_factory):
    """Per-module SQLite DB so org/user creation cannot collide with the
    rest of the suite (same isolation pattern as test_websocket_auth)."""
    import picosentry.serve.database.manager as db_mod
    import picosentry.serve.services.auth as auth_mod
    import picosentry.serve.services.orgs as orgs_mod

    original_db = db_mod.db
    db_path = tmp_path_factory.mktemp("ws_org") / "org.db"
    isolated = DatabaseManager(db_path=db_path)
    db_mod.db = isolated
    auth_mod.db = isolated
    orgs_mod.db = isolated
    yield isolated
    db_mod.db = original_db
    auth_mod.db = original_db
    orgs_mod.db = original_db
    isolated.close()


def _make_org_user(db: DatabaseManager, slug: str) -> dict[str, Any]:
    from picosentry.serve.services.auth import AuthService
    from picosentry.serve.services.orgs import Organization

    auth = AuthService(db=db)
    username = f"wsorg_{slug}_{int(time.time() * 1000)}_{uuid.uuid4().hex[:6]}"
    password = "testpassword123"
    user_id = auth.create_user(username, password, role="viewer")
    assert user_id is not None
    created = Organization.create(name=f"Org {slug}", slug=f"{slug}-{uuid.uuid4().hex[:8]}", owner_user_id=user_id)
    assert created and created.get("org_id"), "org creation failed"
    token = auth.authenticate(username, password)
    assert token is not None
    return {"user_id": user_id, "org_id": created["org_id"], "token": token}


def test_org_events_are_tenant_isolated(_isolated_ws_db) -> None:
    """org-1 must not see org-2's run events; each org sees its own; a
    system event (org_id=None) reaches both."""
    org1 = _make_org_user(_isolated_ws_db, "alpha")
    org2 = _make_org_user(_isolated_ws_db, "beta")

    client = TestClient(app)
    with (
        client.websocket_connect(f"/ws?token={org1['token']}") as ws1,
        client.websocket_connect(f"/ws?token={org2['token']}") as ws2,
    ):
        for ws in (ws1, ws2):
            welcome = _json(ws.receive_text())  # auth welcome
            assert welcome["type"] == "auth"
            ws.send_text('{"action": "subscribe", "channels": ["*"]}')
            ack = _json(ws.receive_text())
            assert ack["type"] == "subscribed"

        import asyncio

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                ws_manager.broadcast("project.run.started", {"run_id": "r1"}, org_id=org1["org_id"])
            )
            loop.run_until_complete(
                ws_manager.broadcast("project.run.started", {"run_id": "r2"}, org_id=org2["org_id"])
            )
            loop.run_until_complete(ws_manager.broadcast("system.notice", {"what": "maintenance"}))
        finally:
            loop.close()

        # org-1 socket: own event first, then the system event. It must
        # never observe org-2's r2 — the queue order proves filtering.
        m1a = _json(ws1.receive_text())
        m1b = _json(ws1.receive_text())
        assert m1a["payload"]["run_id"] == "r1"
        assert m1a["org_id"] == str(org1["org_id"])
        assert m1b["type"] == "system.notice"
        assert m1b["org_id"] is None

        # org-2 socket: only its own event + the system event.
        m2a = _json(ws2.receive_text())
        m2b = _json(ws2.receive_text())
        assert m2a["payload"]["run_id"] == "r2"
        assert m2b["type"] == "system.notice"


def test_subscribe_channel_cap_and_name_validation() -> None:
    assert validate_channels(["*"]) == ["*"]
    assert validate_channels(["project.run.started"]) == ["project.run.started"]

    with pytest.raises(ValueError, match="Too many channels"):
        validate_channels([f"ch{i}" for i in range(17)])

    for bad in ["", "has space", "bad!name", "x" * 65, "ch\nnel"]:
        with pytest.raises(ValueError, match="Invalid channel name"):
            validate_channels([bad])


def test_subscribe_rejects_oversized_list_with_error_frame(_isolated_ws_db) -> None:
    org1 = _make_org_user(_isolated_ws_db, "cap")
    client = TestClient(app)
    with client.websocket_connect(f"/ws?token={org1['token']}") as ws:
        _json(ws.receive_text())  # auth welcome
        ws.send_text(json_dumps({"action": "subscribe", "channels": [f"ch{i}" for i in range(17)]}))
        reply = _json(ws.receive_text())
        assert reply["type"] == "error"
        assert "Too many channels" in reply["message"]

        ws.send_text(json_dumps({"action": "subscribe", "channels": ["bad name!"]}))
        reply = _json(ws.receive_text())
        assert reply["type"] == "error"
        assert "Invalid channel name" in reply["message"]


@pytest.mark.asyncio
async def test_disconnect_cleans_empty_channel_sets() -> None:
    manager = ConnectionManager()
    ws_a, ws_b = _FakeSocket(), _FakeSocket()
    await manager.connect(ws_a, channels=["runs"], org_id=1)
    await manager.connect(ws_b, channels=["runs"], org_id=1)
    assert "runs" in manager.connections

    await manager.disconnect(ws_a)
    assert "runs" in manager.connections  # ws_b still subscribed

    await manager.disconnect(ws_b)
    assert "runs" not in manager.connections  # empty set removed (B8)
    assert manager.client_channels == {}
    assert manager.client_orgs == {}


@pytest.mark.asyncio
async def test_manager_level_org_fanout() -> None:
    manager = ConnectionManager()
    org1_sock, org2_sock, orgless_sock = _FakeSocket(), _FakeSocket(), _FakeSocket()
    await manager.connect(org1_sock, channels=["*"], org_id=1)
    await manager.connect(org2_sock, channels=["*"], org_id=2)
    await manager.connect(orgless_sock, channels=["*"], org_id=None)

    await manager.broadcast("project.run.completed", {"run_id": "x"}, org_id=1)
    assert len(org1_sock.sent) == 1
    assert org2_sock.sent == []
    assert orgless_sock.sent == []  # org-less sockets never see org-stamped events

    await manager.broadcast("system.notice", {"w": 1})
    assert len(org1_sock.sent) == 2
    assert len(org2_sock.sent) == 1
    assert len(orgless_sock.sent) == 1


class _FakeSocket:
    def __init__(self):
        self.sent: list[str] = []

    async def accept(self):
        pass

    async def send_text(self, message: str):
        self.sent.append(message)


def _json(raw: str) -> dict[str, Any]:
    import json

    return json.loads(raw)


def json_dumps(obj: dict[str, Any]) -> str:
    import json

    return json.dumps(obj)
