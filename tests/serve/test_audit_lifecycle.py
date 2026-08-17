"""WO4.0.0-004: audit lifecycle — retention x tamper-evidence interactions.

Purge and verify shipped the same day and were only tested separately; here
they run together: purge-then-verify must pass (authorized gaps), tampering
and unrecorded deletions must still fail, blocked requests (429/413) must be
audited with request-id correlation, audit rows must carry org_id, and drop
counters must be exported.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from picosentry._core.models import Confidence, Severity
from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.services.audit_chain import append_audit_row, verify_audit_chain
from picosentry.serve.services.audit_cleanup import SQLITE_TS, purge_audit_logs


@pytest.fixture
def audit_db(tmp_path, monkeypatch):
    import picosentry.serve.services.audit_cleanup as cleanup_mod

    mgr = DatabaseManager(db_path=tmp_path / "audit.db")
    monkeypatch.setattr(cleanup_mod, "db", mgr)
    return mgr


def _append(mgr: DatabaseManager, *, org_id: int | None = None, severity: str = "low") -> None:
    assert append_audit_row(
        action="GET",
        user_id=1,
        resource_type="api",
        resource_id="/x",
        details={"k": "v"},
        ip_address="127.0.0.1",
        user_agent="pytest",
        severity=severity,
        org_id=org_id,
        database=mgr,
    )


def _backdate(mgr: DatabaseManager, row_id: int, days: int) -> None:
    old = datetime.now(timezone.utc) - timedelta(days=days)
    mgr.execute("UPDATE audit_log SET created_at = ? WHERE id = ?", (old.strftime(SQLITE_TS), row_id))


class TestPurgeThenVerify:
    def test_severity_purge_of_middle_rows_keeps_verify_green(self, audit_db):
        for _ in range(5):
            _append(audit_db)
        _backdate(audit_db, 2, 40)
        _backdate(audit_db, 3, 40)
        _backdate(audit_db, 4, 40)  # low + 40d > 30d retention -> purged

        result = purge_audit_logs()
        assert result["low"]["deleted"] == 3

        outcome = verify_audit_chain(database=audit_db)
        assert outcome["valid"] is True, outcome
        assert outcome["rows_checked"] == 3  # ids 1, 5 + the gap marker

    def test_bulk_purge_of_head_rows_keeps_verify_green(self, audit_db):
        for _ in range(4):
            _append(audit_db)
        _backdate(audit_db, 1, 10)
        _backdate(audit_db, 2, 10)

        result = purge_audit_logs(retention_days=5)
        assert result["deleted"] == 2

        outcome = verify_audit_chain(database=audit_db)
        assert outcome["valid"] is True, outcome

    def test_cross_tenant_purge_keeps_every_slice_verifiable(self, audit_db):
        for org in (1, 2, 1, 2):
            _append(audit_db, org_id=org)
        _backdate(audit_db, 1, 40)  # org 1's rows
        _backdate(audit_db, 3, 40)

        purge_audit_logs(org_id=1)

        assert verify_audit_chain(org_id=1, database=audit_db)["valid"] is True
        assert verify_audit_chain(org_id=2, database=audit_db)["valid"] is True
        assert verify_audit_chain(database=audit_db)["valid"] is True

    def test_tampering_after_purge_is_still_detected(self, audit_db):
        for _ in range(5):
            _append(audit_db)
        _backdate(audit_db, 3, 40)
        purge_audit_logs()

        audit_db.execute("UPDATE audit_log SET action = 'HACKED' WHERE id = 5")

        outcome = verify_audit_chain(database=audit_db)
        assert outcome["valid"] is False
        assert "tampered" in outcome["violation"]

    def test_unrecorded_deletion_is_still_flagged(self, audit_db):
        for _ in range(4):
            _append(audit_db)

        audit_db.execute("DELETE FROM audit_log WHERE id = 2")  # not via purge

        outcome = verify_audit_chain(database=audit_db)
        assert outcome["valid"] is False
        assert "deleted link" in outcome["violation"]


def _audit_rows(status: int) -> list[dict]:
    rows = _audit_rows_all()
    return [r for r in rows if r["details"] and json.loads(r["details"]).get("status_code") == status]


def _audit_rows_all() -> list[dict]:
    from picosentry.serve.database.manager import db

    return db.execute("SELECT details, org_id, action FROM audit_log")


def _find_rate_limiter(app):
    from picosentry.serve.middleware.rate_limit import RateLimitMiddleware

    obj = app.middleware_stack
    while obj is not None:
        if isinstance(obj, RateLimitMiddleware):
            return obj
        obj = getattr(obj, "app", None)
    return None


class TestBlockedRequestsAudited:
    def test_rate_limited_429_reaches_audit_log_with_request_id(self, client, monkeypatch):
        from picosentry.serve.api.server import app

        rl = _find_rate_limiter(app)
        assert rl is not None, "RateLimitMiddleware not in stack"
        monkeypatch.setattr(rl, "max_requests_per_ip", 2)
        rl.ip_requests.clear()

        statuses = [client.get("/api/v1/__definitely_not_a_route__").status_code for _ in range(4)]
        assert 429 in statuses

        blocked = _audit_rows(429)
        assert blocked, "429 responses were not audited"
        details = json.loads(blocked[0]["details"])
        assert details["request_id"], "blocked request lost the request-id correlation"
        rl.ip_requests.clear()

    def test_oversized_413_reaches_audit_log(self, client):
        response = client.post(
            "/api/v1/auth/login",
            content=b"x" * (10 * 1024 * 1024 + 1),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413

        blocked = _audit_rows(413)
        assert blocked
        assert json.loads(blocked[0]["details"])["request_id"]


class TestAuditOrgStamping:
    def _projects_rows(self) -> list[dict]:
        return [r for r in _audit_rows_all() if json.loads(r["details"]).get("path") == "/api/v1/projects"]

    def test_api_key_request_stamps_org(self, client):
        from picosentry.serve.services.auth import AuthService
        from picosentry.serve.services.orgs import Organization

        auth = AuthService()
        owner = auth.create_user(f"org-owner-{uuid4().hex[:8]}", "Passw0rd!x")
        created = Organization.create("Acme", f"acme-{uuid4().hex[:8]}", owner)
        key = auth.create_api_key(owner, "audit-test", org_id=created["org_id"])
        assert key

        client.get("/api/v1/projects", headers={"X-API-Key": key})

        rows = self._projects_rows()
        assert rows and rows[-1]["org_id"] == created["org_id"], "API-key audit row not org-stamped"

    def test_bearer_request_stamps_org_from_token_claim(self, client):
        from picosentry.serve.services.auth import AuthService
        from picosentry.serve.services.orgs import Organization

        auth = AuthService()
        username = f"org-owner-{uuid4().hex[:8]}"
        owner = auth.create_user(username, "Passw0rd!x")
        created = Organization.create("Beta", f"beta-{uuid4().hex[:8]}", owner)
        token = auth.login(username, "Passw0rd!x")["token"]
        assert auth.validate_token(token)["org_id"] == created["org_id"]

        client.get("/api/v1/projects", headers={"Authorization": f"Bearer {token}"})

        rows = self._projects_rows()
        assert rows and rows[-1]["org_id"] == created["org_id"], "Bearer audit row not org-stamped"


class TestDropCounters:
    def test_writer_drop_sets_global_gauge(self, monkeypatch):
        from picosentry.serve.middleware.audit import _AuditWriter
        from picosentry.serve.services.metrics import metrics

        block = threading.Event()
        monkeypatch.setattr("picosentry.serve.services.audit_chain.append_audit_row", lambda **kw: block.wait())
        writer = _AuditWriter(maxsize=1)
        assert writer.submit({}) is not None  # picked up; handler blocks
        deadline = time.monotonic() + 2.0
        while not writer._queue.empty() and time.monotonic() < deadline:
            time.sleep(0.001)  # let the writer thread take the blocking item
        assert writer.submit({}) is not None  # queued
        assert writer.submit({}) is None  # queue full -> dropped

        assert writer.dropped == 1
        assert metrics.global_gauges["dropped_audit_records"] == 1
        block.set()

    def test_engine_backpressure_drop_sets_global_gauge(self):
        from picosentry.serve.services.correlation.engine import CorrelationEngine
        from picosentry.serve.services.correlation.models import CorrelatedEvent
        from picosentry.serve.services.metrics import metrics

        engine = CorrelationEngine()
        engine._max_events_per_minute = 0
        event = CorrelatedEvent(
            artifact_id="pkg@1.0.0",
            layer="scan",
            rule_id="L2-TYPO-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            target="test-project",
            title="Typosquat package detected",
            detail="pkg is a typosquat",
            timestamp="2026-01-01T00:00:00Z",
            run_id="run-001",
        )

        engine.ingest(event)

        assert engine.dropped_events == 1
        assert metrics.global_gauges["dropped_correlation_events"] >= 1

    def test_prometheus_exports_global_gauges(self):
        from picosentry.serve.services.metrics import metrics

        metrics.set_global_gauge("dropped_audit_records", 7)
        text = metrics.to_prometheus()

        assert "picoshogun_dropped_audit_records 7" in text
