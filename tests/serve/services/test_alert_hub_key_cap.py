"""AlertHub cooldown bookkeeping must be bounded (probe: unbounded key growth)."""

from __future__ import annotations

from picosentry.serve.services import alert_hub as alert_hub_mod
from picosentry.serve.services.alert_hub import AlertHub


class TestRecentAlertsKeyCap:
    def test_keys_capped_and_oldest_evicted(self):
        hub = AlertHub()
        for i in range(alert_hub_mod._MAX_RECENT_KEYS + 100):
            hub.send(f"proj-{i}", "alert_type", "low", "msg", channels=[])

        assert len(hub.recent_alerts) <= alert_hub_mod._MAX_RECENT_KEYS
        assert "None:proj-0:alert_type" not in hub.recent_alerts  # oldest evicted (None = org-less)
        newest = f"None:proj-{alert_hub_mod._MAX_RECENT_KEYS + 99}:alert_type"
        assert newest in hub.recent_alerts

    def test_hot_key_survives_eviction(self):
        hub = AlertHub()
        for i in range(alert_hub_mod._MAX_RECENT_KEYS + 10):
            hub.send(f"bulk-{i}", "t", "low", "msg", channels=[])
        hub.send("hot", "t", "low", "msg", channels=[])  # send() refreshes recency
        for i in range(50):  # further pressure must not evict the refreshed key
            hub.send(f"tail-{i}", "t", "low", "msg", channels=[])
        assert "None:hot:t" in hub.recent_alerts
        assert len(hub.recent_alerts) <= alert_hub_mod._MAX_RECENT_KEYS
