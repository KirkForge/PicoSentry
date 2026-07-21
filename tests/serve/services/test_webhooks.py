"""Unit tests for the webhook manager and SSRF guard."""

from picosentry.serve.services.webhooks import Webhook, WebhookManager, _is_safe_webhook_url


def _fake_resolver(ips):
    def _resolve(hostname):
        return ips

    return _resolve


class TestWebhookURLSafety:
    """SSRF prevention for webhook URLs."""

    def test_public_https_url_allowed(self):
        ok, reason = _is_safe_webhook_url("https://example.com/hook")
        assert ok is True
        assert reason == "OK"

    def test_http_url_allowed(self):
        ok, _reason = _is_safe_webhook_url("http://example.com/hook")
        assert ok is True

    def test_file_scheme_rejected(self):
        ok, reason = _is_safe_webhook_url("file:///etc/passwd")
        assert ok is False
        assert "file" in reason.lower()

    def test_loopback_rejected(self):
        ok, reason = _is_safe_webhook_url(
            "http://localhost/hook",
            dns_resolver=_fake_resolver(["127.0.0.1"]),
        )
        assert ok is False
        assert "127.0.0.1" in reason

    def test_private_ip_rejected(self):
        ok, reason = _is_safe_webhook_url(
            "http://internal/hook",
            dns_resolver=_fake_resolver(["192.168.1.5"]),
        )
        assert ok is False
        assert "192.168.1.5" in reason

    def test_unresolvable_hostname_rejected(self):
        ok, reason = _is_safe_webhook_url(
            "http://does-not-exist/hook",
            dns_resolver=_fake_resolver(None),
        )
        assert ok is False
        assert "Cannot resolve" in reason

    def test_scheme_only_url_rejected(self):
        ok, reason = _is_safe_webhook_url("http://")
        assert ok is False
        assert "hostname" in reason.lower()


class TestWebhookManagerCreate:
    """WebhookManager.create() must reject malformed URLs with a clean error."""

    def test_create_rejects_scheme_only_url(self):
        manager = WebhookManager(dns_resolver=_fake_resolver(["1.1.1.1"]))
        import pytest

        with pytest.raises(ValueError, match="hostname"):
            manager.create("bad-hook", "http://", ["alert"])


class TestWebhookDispatch:
    """Dispatch must tolerate request failures without leaking internal errors."""

    def test_dispatch_tolerates_timeout(self, monkeypatch):
        from datetime import datetime, timezone

        import requests

        manager = WebhookManager(dns_resolver=_fake_resolver(["1.1.1.1"]))
        # Isolate from any webhooks loaded from the shared test database.
        manager.webhooks = {}
        manager.webhooks["timeout-hook"] = Webhook(
            id=1,
            name="timeout-hook",
            url="https://example.com/hook",
            secret="secret",
            events=["alert"],
            active=True,
            retries=0,
            created_at=datetime.now(timezone.utc),
            org_id=1,
            pinned_ips=["1.1.1.1"],
        )

        def _raise(*args, **kwargs):
            raise requests.Timeout("connection timed out")

        monkeypatch.setattr(requests, "post", _raise)
        # Pin the re-resolver so the create-time pinned set still matches.
        monkeypatch.setattr(
            "picosentry.serve.services.webhooks._resolve_hostname",
            _fake_resolver(["1.1.1.1"]),
        )

        results = manager.dispatch("alert", {"msg": "test"})
        assert len(results) == 1
        assert results[0]["webhook"] == "timeout-hook"
        assert results[0]["success"] is False
        assert results[0]["status"] == 0
        assert "timed out" in results[0]["error"]

    def test_dispatch_rejects_dns_rebind(self, monkeypatch):
        """A hostname that resolves to a different IP at dispatch time than
        at create time must be rejected (PicoSentry-HIGH-2)."""
        from datetime import datetime, timezone

        import requests

        # Create-time resolver says public IP; dispatch-time resolver says
        # 127.0.0.1.
        manager = WebhookManager(dns_resolver=_fake_resolver(["1.1.1.1"]))
        manager.webhooks = {}
        manager.webhooks["rebind-hook"] = Webhook(
            id=2,
            name="rebind-hook",
            url="https://evil.example/hook",
            secret="secret",
            events=["alert"],
            active=True,
            retries=0,
            created_at=datetime.now(timezone.utc),
            org_id=1,
            pinned_ips=["1.1.1.1"],
        )

        posted = {"count": 0}

        def _capture_post(*args, **kwargs):
            posted["count"] += 1
            return requests.Response()

        monkeypatch.setattr(requests, "post", _capture_post)
        monkeypatch.setattr(
            "picosentry.serve.services.webhooks._resolve_hostname",
            _fake_resolver(["127.0.0.1"]),
        )

        results = manager.dispatch("alert", {"msg": "test"})
        assert len(results) == 1
        assert results[0]["webhook"] == "rebind-hook"
        assert results[0]["success"] is False
        assert results[0]["status"] == 0
        assert "rebind" in results[0]["error"].lower()
        assert posted["count"] == 0
