"""Tests for webhook notifications."""

import json

from picosentry.sandbox.webhooks import (
    WebhookConfig,
    WebhookDispatcher,
    WebhookEvent,
    WebhookPayload,
    _sign_payload,
)


class TestWebhookConfig:
    def test_defaults(self):
        config = WebhookConfig(url="https://example.com/hook")
        assert config.url == "https://example.com/hook"
        assert config.min_severity == "high"
        assert config.max_retries == 3
        assert config.enabled is True

    def test_to_dict_hides_secret(self):
        config = WebhookConfig(url="https://example.com", secret="super-secret")
        d = config.to_dict()
        assert d["secret"] == "***"


class TestWebhookPayload:
    def test_to_json(self):
        payload = WebhookPayload(
            event="scan_alert",
            timestamp="2025-01-01T00:00:00Z",
            data={"package": "evil-pkg"},
            signature="sha256=abc",
        )
        j = payload.to_json()
        data = json.loads(j)
        assert data["event"] == "scan_alert"
        assert data["data"]["package"] == "evil-pkg"


class TestSignPayload:
    def test_sign_with_secret(self):
        sig = _sign_payload('{"test": true}', "my-secret")
        assert sig.startswith("sha256=")
        assert len(sig) > 10

    def test_empty_secret(self):
        sig = _sign_payload('{"test": true}', "")
        assert sig == ""

    def test_deterministic(self):
        sig1 = _sign_payload("hello", "secret")
        sig2 = _sign_payload("hello", "secret")
        assert sig1 == sig2


class TestWebhookDispatcher:
    def test_add_and_list(self):
        d = WebhookDispatcher()
        d.add_webhook(WebhookConfig(url="https://a.com"))
        d.add_webhook(WebhookConfig(url="https://b.com"))
        webhooks = d.list_webhooks()
        assert len(webhooks) == 2

    def test_remove_webhook(self):
        d = WebhookDispatcher()
        d.add_webhook(WebhookConfig(url="https://a.com"))
        d.add_webhook(WebhookConfig(url="https://b.com"))
        d.remove_webhook("https://a.com")
        assert len(d.list_webhooks()) == 1

    def test_severity_filter_skips(self):
        d = WebhookDispatcher()
        d.add_webhook(WebhookConfig(url="https://a.com", min_severity="high"))
        result = d.notify(
            event=WebhookEvent.SCAN_ALERT,
            data={"package": "pkg"},
            severity="low",
        )
        assert result["skipped"] == 1

    def test_event_filter_skips(self):
        d = WebhookDispatcher()
        d.add_webhook(WebhookConfig(url="https://a.com", events=["policy_change"]))
        result = d.notify(
            event=WebhookEvent.SCAN_ALERT,
            data={},
        )
        assert result["skipped"] == 1

    def test_disabled_webhook_skipped(self):
        d = WebhookDispatcher()
        d.add_webhook(WebhookConfig(url="https://a.com", enabled=False))
        result = d.notify(event=WebhookEvent.SCAN_ALERT, data={})
        assert result["skipped"] == 1

    def test_wildcard_event(self):
        d = WebhookDispatcher()
        d.add_webhook(WebhookConfig(url="https://a.com", events=["*"]))
        # Will attempt delivery (will fail since URL is fake, but not skipped)
        result = d.notify(event=WebhookEvent.SCAN_ALERT, data={}, severity="critical")
        assert result["failed"] == 1  # attempted but URL unreachable

    def test_from_config(self):
        config = {
            "webhooks": [
                {"url": "https://a.com", "events": ["scan_alert"], "min_severity": "critical"},
                {"url": "https://b.com", "events": ["*"], "enabled": False},
            ]
        }
        d = WebhookDispatcher.from_config(config)
        assert len(d.list_webhooks()) == 2
