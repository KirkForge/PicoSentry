"""WO6.0.0-011: GET /events/history must round-trip org-stamped events
(id is a uuid str, not an int) and include system events (org_id=None)
for org admins, matching WS broadcast semantics.

The latent 500 (ResponseValidationError int_parsing) was masked by
empty histories in every existing test.
"""

from __future__ import annotations

import pytest

from picosentry.serve.services.event_bus import event_bus

from tests.serve._integration_helpers import _auth_headers, _register_and_login


@pytest.fixture(autouse=True)
def _clear_event_history():
    event_bus.clear_history()
    yield
    event_bus.clear_history()


class TestEventsHistoryRoundTrip:
    def test_org_stamped_event_round_trips_with_uuid_id(self, client):
        """Publish one org-stamped event → GET /events/history 200 with the
        row round-tripping (id as str). Pre-fix this 500'd with
        ResponseValidationError int_parsing (EventHistoryItem.id was int)."""
        token, _ = _register_and_login(client, role="admin")
        org_id = client.get("/orgs", headers=_auth_headers(token)).json()["orgs"][0]["id"]

        event = event_bus.publish(
            "test.wo6.roundtrip",
            {"k": "v"},
            source="wo6-test",
            org_id=str(org_id),
        )

        resp = client.get("/events/history", headers=_auth_headers(token))
        assert resp.status_code == 200, resp.text
        items = resp.json()
        ids = [item["id"] for item in items]
        assert event.id in ids, f"published event id {event.id!r} not in {ids}"
        match = next(item for item in items if item["id"] == event.id)
        assert match["type"] == "test.wo6.roundtrip"
        assert match["source"] == "wo6-test"
        assert match["payload"] == {"k": "v"}
        assert match["priority"] == "normal"
        # id is a uuid str, not coerced to int.
        assert isinstance(match["id"], str)
        assert match["id"] == event.id

    def test_system_event_visible_to_org_admin(self, client):
        """org_id=None system events are broadcast to every authenticated WS
        socket (websocket_manager.broadcast); the queryable history surface
        must include them too. Pre-fix admin.py filtered org_id=None out."""
        token, _ = _register_and_login(client, role="admin")
        client.get("/orgs", headers=_auth_headers(token)).json()["orgs"][0]["id"]

        event_bus.publish(
            "scheduler.lease.acquired",
            {"worker": "w1"},
            source="scheduler",
            org_id=None,
        )

        resp = client.get("/events/history", headers=_auth_headers(token))
        assert resp.status_code == 200, resp.text
        types = [item["type"] for item in resp.json()]
        assert "scheduler.lease.acquired" in types, "system event hidden from org admin"

    def test_cross_org_isolation_preserved(self, client):
        """An event stamped with org B must NOT appear in org A's history
        (only system + own-org events are visible)."""
        token_a, _ = _register_and_login(client, role="admin", suffix="a")
        org_a = client.get("/orgs", headers=_auth_headers(token_a)).json()["orgs"][0]["id"]

        token_b, _ = _register_and_login(client, role="admin", suffix="b")
        org_b = client.get("/orgs", headers=_auth_headers(token_b)).json()["orgs"][0]["id"]
        assert org_a != org_b

        event_bus.publish("test.wo6.isolation", {"who": "b"}, source="wo6-test", org_id=str(org_b))

        resp = client.get("/events/history", headers=_auth_headers(token_a))
        assert resp.status_code == 200, resp.text
        types = [item["type"] for item in resp.json()]
        assert "test.wo6.isolation" not in types, "org B event leaked into org A history"
