"""WO7.0.0-028: acknowledge_alert sets acknowledged=1, not sent=1."""

from __future__ import annotations

from picosentry.serve.database.manager import db
from tests.serve._integration_helpers import _auth_headers, _register_with_org


def test_acknowledge_sets_acknowledged_not_sent(client):
    """acknowledge_alert sets acknowledged=1, sent stays 0."""
    token, org_id, _slug = _register_with_org(client, role="admin", slug_prefix="ack-alert")

    db.execute_insert(
        "INSERT INTO alerts (project_id, alert_type, severity, message, channel, org_id) VALUES (?, ?, ?, ?, ?, ?)",
        ("proj", "test", "high", "test alert", "syslog", org_id),
    )
    alert = db.execute_one("SELECT id, acknowledged, sent FROM alerts WHERE org_id = ?", (org_id,))
    assert alert is not None
    alert_id = alert["id"]
    assert alert["acknowledged"] in (0, False, None)

    resp = client.post(f"/alerts/{alert_id}/acknowledge", headers=_auth_headers(token))
    assert resp.status_code == 200, resp.text

    row = db.execute_one("SELECT acknowledged, sent FROM alerts WHERE id = ?", (alert_id,))
    assert row["acknowledged"] in (1, True), f"acknowledged should be 1, got {row['acknowledged']}"
    assert row["sent"] in (0, False, None), f"sent should remain 0, got {row['sent']}"


def test_acknowledged_and_sent_independent(client):
    """An already-sent alert can still be acknowledged; both flags are independent."""
    token, org_id, _slug = _register_with_org(client, role="admin", slug_prefix="ack-ind")

    db.execute_insert(
        "INSERT INTO alerts (project_id, alert_type, severity, message, channel, org_id, sent) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("proj2", "test", "high", "delivered alert", "syslog", org_id, 1),
    )
    alert = db.execute_one("SELECT id, acknowledged, sent FROM alerts WHERE org_id = ? AND sent = 1", (org_id,))
    assert alert is not None
    alert_id = alert["id"]

    resp = client.post(f"/alerts/{alert_id}/acknowledge", headers=_auth_headers(token))
    assert resp.status_code == 200, resp.text

    row = db.execute_one("SELECT acknowledged, sent FROM alerts WHERE id = ?", (alert_id,))
    assert row["acknowledged"] in (1, True)
    assert row["sent"] in (1, True), "sent should remain 1 (was already delivered)"
