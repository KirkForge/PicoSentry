"""Unit tests for AlertHub exception-narrowing paths."""

from __future__ import annotations

import logging

import pytest

from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.services.alert_hub import AlertHub, _ALERT_CHANNEL_ERRORS


def _raise(exc: BaseException):
    def _inner(*args, **kwargs):
        raise exc

    return _inner


class TestAlertHubHardening:
    """Alert delivery must tolerate expected channel failures but surface programmer errors."""

    @pytest.fixture
    def isolated_hub(self, tmp_path, monkeypatch):
        db = DatabaseManager(db_path=tmp_path / "alerts.db", backend="sqlite")
        monkeypatch.setattr("picosentry.serve.services.alert_hub.db", db)
        hub = AlertHub()
        # Only syslog channel so we don't need requests or SMTP.
        monkeypatch.setattr(
            hub,
            "_get_default_channels",
            lambda: ["syslog"],
        )
        return hub

    def test_expected_channel_failure_is_logged_and_continues(self, isolated_hub, caplog, monkeypatch):
        monkeypatch.setattr(
            isolated_hub,
            "_syslog_notify",
            _raise(RuntimeError("syslog down")),
        )

        with caplog.at_level(logging.ERROR, logger="picoshogun.Alerts"):
            success = isolated_hub.send("proj-1", "test", "high", "boom")

        assert not success
        assert any("Alert delivery failed (syslog)" in r.message for r in caplog.records)
        # Alert row should exist with retry_count incremented.
        rows = isolated_hub.get_alert_stats(hours=1)
        assert rows["high"]["total"] == 1
        assert rows["high"]["pending"] == 1

    def test_unexpected_channel_error_propagates(self, isolated_hub, monkeypatch):
        monkeypatch.setattr(
            isolated_hub,
            "_syslog_notify",
            _raise(AttributeError("programmer mistake")),
        )

        with pytest.raises(AttributeError, match="programmer mistake"):
            isolated_hub.send("proj-1", "test", "high", "boom")

    def test_channel_errors_tuple_does_not_include_base_exception(self):
        assert BaseException not in _ALERT_CHANNEL_ERRORS
        assert Exception not in _ALERT_CHANNEL_ERRORS


class TestChannelDeliveryTruthfulness:
    """WO5.0.0-008: a failed channel delivery must be recorded sent=0 with
    retry_count incremented and send() returning False — the channel helpers
    no longer swallow their own delivery exceptions."""

    @pytest.fixture
    def hub_db(self, tmp_path, monkeypatch):
        import picosentry.serve.services.alert_hub as hub_mod

        mgr = DatabaseManager(db_path=tmp_path / "alerts.db", backend="sqlite")
        monkeypatch.setattr(hub_mod, "db", mgr)
        return mgr

    def test_unreachable_webhook_recorded_unsent_and_retried(self, hub_db, monkeypatch):
        import requests

        from picosentry.serve.config.settings import settings

        monkeypatch.setattr(settings.alerts, "discord_webhook", "https://example.com/hook")
        monkeypatch.setattr(requests, "post", _raise(requests.ConnectionError("webhook unreachable")))

        hub = AlertHub()
        sent = hub.send("proj-1", "delivery", "high", "boom", channels=["discord"])

        assert sent is False
        row = hub_db.execute_one("SELECT sent, retry_count FROM alerts WHERE channel = 'discord'")
        assert row["sent"] == 0
        assert row["retry_count"] == 1
        stats = hub.get_alert_stats(hours=1)
        assert stats["high"]["pending"] == 1

    def test_unreachable_slack_recorded_unsent(self, hub_db, monkeypatch):
        import requests

        from picosentry.serve.config.settings import settings

        monkeypatch.setattr(settings.alerts, "slack_webhook", "https://example.com/hook")
        monkeypatch.setattr(requests, "post", _raise(requests.Timeout("slack timed out")))

        hub = AlertHub()
        assert hub.send("proj-1", "delivery", "high", "boom", channels=["slack"]) is False
        row = hub_db.execute_one("SELECT sent, retry_count FROM alerts WHERE channel = 'slack'")
        assert row["sent"] == 0
        assert row["retry_count"] == 1

    def test_smtp_failure_recorded_unsent(self, hub_db, monkeypatch):
        import smtplib

        from picosentry.serve.config.settings import settings

        monkeypatch.setattr(settings.alerts, "email_smtp_host", "smtp.example.com")
        monkeypatch.setattr(settings.alerts, "email_to", ["dest@example.com"])
        monkeypatch.setattr(smtplib, "SMTP", _raise(OSError("smtp down")))

        hub = AlertHub()
        assert hub.send("proj-1", "delivery", "high", "boom", channels=["email"]) is False
        row = hub_db.execute_one("SELECT sent, retry_count FROM alerts WHERE channel = 'email'")
        assert row["sent"] == 0
        assert row["retry_count"] == 1

    def test_successful_delivery_still_marks_sent(self, hub_db, monkeypatch):
        import requests

        from picosentry.serve.config.settings import settings

        monkeypatch.setattr(settings.alerts, "discord_webhook", "https://example.com/hook")

        def _ok(*args, **kwargs):
            return requests.Response()

        monkeypatch.setattr(requests, "post", _ok)

        hub = AlertHub()
        assert hub.send("proj-1", "delivery", "high", "fine", channels=["discord"]) is True
        row = hub_db.execute_one("SELECT sent, retry_count FROM alerts WHERE channel = 'discord'")
        assert row["sent"] == 1
        assert row["retry_count"] == 0


class TestWebhookUrlEnvPrefix:
    """WO5.0.0-027 rider: PICOSHOGUN_-prefixed webhook URLs are canonical;
    the unprefixed legacy names still work with a deprecation log."""

    def test_prefixed_canonical_and_legacy_fallback(self, monkeypatch, caplog):
        import logging

        import picosentry.serve.config.settings as settings_mod

        monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)
        monkeypatch.delenv("PICOSHOGUN_DISCORD_WEBHOOK_URL", raising=False)

        assert settings_mod.AlertConfig().discord_webhook is None

        monkeypatch.setenv("PICOSHOGUN_DISCORD_WEBHOOK_URL", "https://canonical.example/hook")
        assert settings_mod.AlertConfig().discord_webhook == "https://canonical.example/hook"

        monkeypatch.delenv("PICOSHOGUN_DISCORD_WEBHOOK_URL")
        monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://legacy.example/hook")
        with caplog.at_level(logging.WARNING, logger="picoshogun.config"):
            assert settings_mod.AlertConfig().discord_webhook == "https://legacy.example/hook"
        assert any("deprecated" in r.message for r in caplog.records)
