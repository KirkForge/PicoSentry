"""WebSocket auth regression suite (P0 fix).

Pins the new connect-time contract on ``GET /ws``:

  1. An unauthenticated client connects with an empty channel set, so
     no event ever reaches them.  ``subscribe`` is rejected until they
     authenticate.
  2. A valid ``?token=`` query string authenticates the client at
     connect time, but the client still must send ``subscribe`` to
     actually receive broadcasts.
  3. An invalid ``?token=`` causes an immediate 4001 close.
  4. The in-band ``{"action": "auth"}`` flow still works as the second
     supported auth path, but is followed by the same explicit
     ``subscribe`` step.
  5. After auth, the client is actually subscribed — a probe broadcast
     reaches them.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from picosentry.serve.api.server import app
from picosentry.serve.services.websocket_manager import ws_manager


@pytest.fixture
def fresh_user() -> dict[str, Any]:
    """Create a fresh viewer user via the service layer and return their
    id, username, password, and a valid JWT — bypassing the registration
    endpoint, which (correctly) only creates viewers and is exercised by
    its own test suite.

    Bypassing the endpoint is fine here: the websocket tests are about
    the ws layer, not the registration API.
    """
    from picosentry.serve.services.auth import AuthService

    auth = AuthService()
    suffix = int(time.time() * 1000)
    username = f"wstest_{suffix}_{uuid.uuid4().hex[:8]}"
    password = "testpassword123"
    user_id = auth.create_user(username, password, role="viewer")
    assert user_id is not None, "could not create test user"
    token = auth.authenticate(username, password)
    assert token is not None
    return {"user_id": user_id, "username": username, "password": password, "token": token}


def test_unauthenticated_socket_gets_no_broadcasts() -> None:
    """An unauthenticated connect must NOT be subscribed to ``*``.

    Previously the server added every connect to ``channels=["*"]``,
    so any subsequent ``ws_manager.broadcast`` reached the socket.  The
    fix: empty channel set on connect, explicit ``subscribe`` required.
    """
    client = TestClient(app)
    with client.websocket_connect("/ws") as ws:
        # The connect itself succeeds.  The server does not push a
        # welcome frame because the client is unauthenticated; that's
        # the safer default.
        # Probe: ask the client to subscribe without auth and expect
        # the error response (not a successful subscription).
        ws.send_text('{"action": "subscribe", "channels": ["*"]}')
        reply = ws.receive_text()
        msg = _json_or_skip(reply)
        assert msg is not None
        assert msg["type"] == "error"
        assert "Authentication required" in msg["message"]


def test_invalid_token_query_string_closes_with_4001() -> None:
    """A bad ``?token=`` must close the socket with code 4001.

    Starlette's TestClient surfaces the server-initiated close as
    ``WebSocketDisconnect`` on the next receive.  Reading inside the
    ``with`` block is what triggers the exception; just entering and
    leaving the block doesn't, because the close frame is processed
    asynchronously.
    """
    from starlette.websockets import WebSocketDisconnect

    client = TestClient(app)
    with client.websocket_connect("/ws?token=this-is-not-a-valid-jwt") as ws:
        with pytest.raises(WebSocketDisconnect) as excinfo:
            ws.receive_text()
    assert excinfo.value.code == 4001


def test_valid_token_query_string_authenticates(fresh_user: dict[str, Any]) -> None:
    """A good ``?token=`` authenticates immediately.  The client is told
    auth succeeded and is reminded to subscribe — auth alone is not
    enough to start receiving events."""
    client = TestClient(app)

    with client.websocket_connect(f"/ws?token={fresh_user['token']}") as ws:
        welcome = _json_or_skip(ws.receive_text())
        assert welcome is not None
        assert welcome["type"] == "auth"
        assert welcome["status"] == "ok"
        assert welcome["user_id"] == fresh_user["user_id"]


def test_valid_token_then_subscribe_receives_broadcast(fresh_user: dict[str, Any]) -> None:
    """After query-string auth AND an explicit subscribe, the client
    receives a probe broadcast.  This is the happy path the dashboard
    front-end takes (auth + subscribe in onopen)."""
    client = TestClient(app)

    with client.websocket_connect(f"/ws?token={fresh_user['token']}") as ws:
        # Drain the auth-welcome frame.
        _json_or_skip(ws.receive_text())

        ws.send_text('{"action": "subscribe", "channels": ["*"]}')
        sub_ack = _json_or_skip(ws.receive_text())
        assert sub_ack is not None
        assert sub_ack["type"] == "subscribed"
        assert "*" in sub_ack["channels"]

        # Probe: inject a broadcast and confirm the socket receives it.
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(ws_manager.broadcast("probe.event", {"hello": "world"}))
        finally:
            loop.close()

        msg = _json_or_skip(ws.receive_text())
        assert msg is not None
        assert msg["type"] == "probe.event"
        assert msg["payload"] == {"hello": "world"}


def test_in_band_auth_flow(fresh_user: dict[str, Any]) -> None:
    """Connect with no query token, send ``action=auth`` in-band, then
    subscribe.  Same contract as the query-string path."""
    client = TestClient(app)

    with client.websocket_connect("/ws") as ws:
        ws.send_text(json_dumps({"action": "auth", "token": fresh_user["token"]}))
        ack = _json_or_skip(ws.receive_text())
        assert ack is not None
        assert ack["type"] == "auth"
        assert ack["status"] == "ok"

        ws.send_text(json_dumps({"action": "subscribe", "channels": ["*"]}))
        sub = _json_or_skip(ws.receive_text())
        assert sub is not None
        assert sub["type"] == "subscribed"


def test_in_band_bad_token_closes_with_4001() -> None:
    """An in-band auth attempt with a bad token closes the socket with
    4001 — same as a bad query-string token.  A probing client should
    not be left with a stale unauthenticated state to keep guessing."""
    from starlette.websockets import WebSocketDisconnect

    client = TestClient(app)
    with client.websocket_connect("/ws") as ws:
        ws.send_text(json_dumps({"action": "auth", "token": "not-a-jwt"}))
        # First read returns the deny frame; the second read observes
        # the server-initiated close.
        deny = _json_or_skip(ws.receive_text())
        assert deny is not None
        assert deny["type"] == "auth"
        assert deny["status"] == "denied"
        with pytest.raises(WebSocketDisconnect) as excinfo:
            ws.receive_text()
    assert excinfo.value.code == 4001


def test_ping_pong(fresh_user: dict[str, Any]) -> None:
    """``{"action": "ping"}`` returns ``{"type": "pong"}``.  Light liveness
    check; also confirms the receive loop processes protocol control
    frames without trying to broadcast them."""
    client = TestClient(app)
    with client.websocket_connect(f"/ws?token={fresh_user['token']}") as ws:
        _json_or_skip(ws.receive_text())  # auth welcome
        ws.send_text(json_dumps({"action": "ping"}))
        reply = _json_or_skip(ws.receive_text())
        assert reply is not None
        assert reply["type"] == "pong"


# ── helpers ───────────────────────────────────────────────────────────


def _json_or_skip(raw: str) -> dict[str, Any] | None:
    """Parse a ws frame as JSON.  Return ``None`` if the server ever
    sends a non-JSON frame so a regression that emits garbage doesn't
    crash the test."""
    import json
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


def json_dumps(obj: dict[str, Any]) -> str:
    import json
    return json.dumps(obj)
