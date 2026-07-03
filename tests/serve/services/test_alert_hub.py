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
