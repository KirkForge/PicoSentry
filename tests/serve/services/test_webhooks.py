"""Unit tests for the webhook manager and SSRF guard."""

import pytest

from picosentry.serve.services.webhooks import (
    Webhook,
    WebhookManager,
    WebhookNameConflict,
    _is_safe_webhook_url,
)


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
        manager.webhooks[1] = Webhook(
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
        assert results[0]["error"] == "webhook delivery failed"

    def test_dispatch_rejects_dns_rebind(self, monkeypatch):
        """A hostname that resolves to a different IP at dispatch time than
        at create time must be rejected (PicoSentry-HIGH-2)."""
        from datetime import datetime, timezone

        import requests

        # Create-time resolver says public IP; dispatch-time resolver says
        # 127.0.0.1.
        manager = WebhookManager(dns_resolver=_fake_resolver(["1.1.1.1"]))
        manager.webhooks = {}
        manager.webhooks[2] = Webhook(
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

    def test_dispatch_forbids_redirects(self, monkeypatch):
        """A 3xx must be treated as failure and requests must be told not to
        follow it — a redirect target was never SSRF-checked or DNS-pinned (B2r)."""
        from datetime import datetime, timezone

        import requests

        manager = WebhookManager(dns_resolver=_fake_resolver(["1.1.1.1"]))
        manager.webhooks = {}
        manager.webhooks[3] = Webhook(
            id=3,
            name="redirect-hook",
            url="https://example.com/hook",
            secret="secret",
            events=["alert"],
            active=True,
            retries=0,
            created_at=datetime.now(timezone.utc),
            org_id=1,
            pinned_ips=["1.1.1.1"],
        )

        captured_kwargs: dict = {}

        def _redirect_post(*args, **kwargs):
            captured_kwargs.update(kwargs)
            response = requests.Response()
            response.status_code = 302
            response.headers["Location"] = "http://127.0.0.1/evil"
            return response

        monkeypatch.setattr(requests, "post", _redirect_post)
        monkeypatch.setattr(
            "picosentry.serve.services.webhooks._resolve_hostname",
            _fake_resolver(["1.1.1.1"]),
        )

        results = manager.dispatch("alert", {"msg": "test"})
        assert len(results) == 1
        assert results[0]["success"] is False
        assert results[0]["status"] == 302
        assert captured_kwargs.get("allow_redirects") is False


class TestPerOrgWebhookIdentity:
    """WO5.0.0-008: webhooks are keyed by id; names are unique per org only."""

    ORG_A = 9101
    ORG_B = 9102

    def _manager(self):
        return WebhookManager(dns_resolver=_fake_resolver(["1.1.1.1"]))

    def test_same_name_two_orgs_both_dispatch(self, monkeypatch):
        import requests

        from picosentry.serve.database.manager import db

        manager = self._manager()
        try:
            id_a = manager.create("ops-alerts", "https://example.com/a", ["chain.escalated"], org_id=self.ORG_A)
            id_b = manager.create("ops-alerts", "https://example.com/b", ["chain.escalated"], org_id=self.ORG_B)
            assert id_a != id_b
            # both survive in the id-keyed registry (name-keying clobbered org A)
            assert {manager.webhooks[id_a].org_id, manager.webhooks[id_b].org_id} == {self.ORG_A, self.ORG_B}

            posted: list[str] = []

            def _capture_post(url, **kwargs):
                posted.append(url)
                response = requests.Response()
                response.status_code = 200
                return response

            monkeypatch.setattr(requests, "post", _capture_post)
            monkeypatch.setattr(
                "picosentry.serve.services.webhooks._resolve_hostname",
                _fake_resolver(["1.1.1.1"]),
            )

            results_a = manager.dispatch("chain.escalated", {}, org_id=self.ORG_A)
            assert posted == ["https://example.com/a"]
            assert all(r["success"] for r in results_a)

            posted.clear()
            manager.dispatch("chain.escalated", {}, org_id=self.ORG_B)
            assert posted == ["https://example.com/b"]
        finally:
            db.execute("DELETE FROM webhooks WHERE name IN ('dup-name', 'ops-alerts')")

    def test_intra_org_duplicate_name_rejected_cross_org_allowed(self):
        from picosentry.serve.database.manager import db

        manager = self._manager()
        manager.create("dup-name", "https://example.com/a", ["alert"], org_id=self.ORG_A)
        try:
            with pytest.raises(WebhookNameConflict):
                manager.create("dup-name", "https://example.com/b", ["alert"], org_id=self.ORG_A)

            # same name in a different org is legitimate
            manager.create("dup-name", "https://example.com/b", ["alert"], org_id=self.ORG_B)
        finally:
            db.execute("DELETE FROM webhooks WHERE name IN ('dup-name', 'ops-alerts')")


class TestWebhookNameUniqueMigration:
    """Migration 20 (webhooks_unique_name_per_org) must merge intra-org
    duplicate rows keeping the newest, leave cross-org same-name rows alone,
    and enforce the partial unique index on (org_id, name) for active rows."""

    def test_migration_dedupes_intra_org_and_keeps_cross_org(self, tmp_path):
        import sqlite3

        from picosentry.serve.database._schema import MIGRATIONS
        from picosentry.serve.database.manager import DatabaseManager

        mgr = DatabaseManager(db_path=tmp_path / "mig.db", backend="sqlite")
        # Simulate legacy state: duplicates predate the unique index.
        mgr.execute("DROP INDEX IF EXISTS idx_webhooks_org_name")
        mgr.execute(
            "INSERT INTO webhooks (name, url, secret, events, active, retries, org_id)"
            " VALUES ('ops-alerts', 'https://example.com/old', 's', '[]', 1, 0, 1)"
        )
        mgr.execute(
            "INSERT INTO webhooks (name, url, secret, events, active, retries, org_id)"
            " VALUES ('ops-alerts', 'https://example.com/new', 's', '[]', 1, 0, 1)"
        )
        mgr.execute(
            "INSERT INTO webhooks (name, url, secret, events, active, retries, org_id)"
            " VALUES ('ops-alerts', 'https://example.com/org2', 's', '[]', 1, 0, 2)"
        )

        migration = next(m for m in MIGRATIONS if m.name == "webhooks_unique_name_per_org")
        # Re-run the migration SQL exactly like the runner does.
        for raw_stmt in migration.sqlite_sql.split(";"):
            stmt = raw_stmt.strip()
            if stmt:
                mgr.execute(stmt)

        rows = mgr.execute("SELECT org_id, url FROM webhooks WHERE active = 1 ORDER BY org_id, url")
        # org 1 kept its newest row; org 2's same-name row survives.
        assert [(r["org_id"], r["url"]) for r in rows] == [
            (1, "https://example.com/new"),
            (2, "https://example.com/org2"),
        ]

        # The partial unique index now rejects an intra-org active duplicate...
        with pytest.raises(sqlite3.IntegrityError):
            mgr.execute(
                "INSERT INTO webhooks (name, url, secret, events, active, retries, org_id)"
                " VALUES ('ops-alerts', 'https://example.com/dup', 's', '[]', 1, 0, 1)"
            )
        # ...but a soft-deleted name can be recreated (index is active-only).
        mgr.execute("UPDATE webhooks SET active = 0 WHERE org_id = 1")
        mgr.execute(
            "INSERT INTO webhooks (name, url, secret, events, active, retries, org_id)"
            " VALUES ('ops-alerts', 'https://example.com/reborn', 's', '[]', 1, 0, 1)"
        )


class TestWebhookWildcardEvents:
    """WO5.0.0-033: events=["*"] (the API default) must dispatch on every event.

    The literal `event in wh.events` match meant default webhooks never fired."""

    @staticmethod
    def _manager_with(events):
        from datetime import datetime, timezone

        manager = WebhookManager(dns_resolver=_fake_resolver(["1.1.1.1"]))
        manager.webhooks = {}
        manager.webhooks[11] = Webhook(
            id=11,
            name="hook",
            url="https://example.com/hook",
            secret="secret",
            events=events,
            active=True,
            retries=0,
            created_at=datetime.now(timezone.utc),
            org_id=1,
            pinned_ips=["1.1.1.1"],
        )
        return manager

    @staticmethod
    def _patch_post(monkeypatch, posted):
        import requests

        def _capture_post(url, **kwargs):
            posted.append(url)
            response = requests.Response()
            response.status_code = 200
            return response

        monkeypatch.setattr(requests, "post", _capture_post)
        monkeypatch.setattr(
            "picosentry.serve.services.webhooks._resolve_hostname",
            _fake_resolver(["1.1.1.1"]),
        )

    def test_wildcard_receives_kill_chain_escalation(self, monkeypatch):
        posted: list[str] = []
        self._patch_post(monkeypatch, posted)
        manager = self._manager_with(["*"])

        results = manager.dispatch("chain.escalated", {"artifact_id": "x"}, org_id=1)

        assert posted == ["https://example.com/hook"]
        assert results and results[0]["success"] is True

    def test_explicit_list_matches_exactly(self, monkeypatch):
        posted: list[str] = []
        self._patch_post(monkeypatch, posted)
        manager = self._manager_with(["chain.escalated"])

        results = manager.dispatch("project.failed", {"project_id": "x"}, org_id=1)
        assert posted == []
        assert results == []

        results = manager.dispatch("chain.escalated", {"artifact_id": "x"}, org_id=1)
        assert posted == ["https://example.com/hook"]
        assert results and results[0]["success"] is True
