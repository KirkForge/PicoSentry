"""WO7.0.0-003 — gRPC Scan audit events must be tenant-tagged and attributable.

The gRPC Scan RPC's _audit_log used hardcoded actor="picodome-grpc" with no
metadata and no target — tenant-scoped audit queries filter on
metadata.get("tenant_id") so gRPC scan events were invisible to every tenant
and unattributable. This gate proves a gRPC Scan call by tenant A produces an
audit row whose metadata["tenant_id"] == A, reachable by tenant A's audit
query, invisible to tenant B, and that the actor is the token hash (not the
hardcoded "picodome-grpc").
"""

from __future__ import annotations

import hashlib
import time
from unittest.mock import MagicMock

import pytest

import picosentry.sandbox.audit.logger as audit_logger_mod
from picosentry.sandbox.audit import AuditEventType, AuditLogger
from picosentry.sandbox.tenant import reset_tenant_registry

TOKEN_ALPHA = "picodome-submit-alpha-tenant-0000000001"
TOKEN_BETA = "picodome-submit-beta-tenant-0000000002"


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _actor(token: str) -> str:
    return _sha(token)[:16]


@pytest.fixture(autouse=True)
def _clean_singletons(tmp_path):
    original_audit = audit_logger_mod._audit_logger
    audit_logger_mod._audit_logger = AuditLogger(log_dir=tmp_path / "audit", max_bytes=1024 * 1024)
    yield
    audit_logger_mod._audit_logger = original_audit
    reset_tenant_registry()


def _setup_tenants():
    from picosentry.sandbox.tenant import TenantContext, TenantId, setup_tenant_registry

    registry = setup_tenant_registry(
        [
            TenantContext(tenant_id=TenantId("alpha")),
            TenantContext(tenant_id=TenantId("beta")),
        ]
    )
    registry.map_token(_sha(TOKEN_ALPHA), TenantId("alpha"))
    registry.map_token(_sha(TOKEN_BETA), TenantId("beta"))
    return registry


def _ctx(token: str):
    ctx = type("Ctx", (), {})()
    ctx.invocation_metadata = lambda: [("authorization", f"Bearer {token}")]
    ctx.is_active = lambda: True
    return ctx


def _make_servicer():
    from picosentry.sandbox.grpc_transport._servicer import PicoDomeServicer

    return PicoDomeServicer(scan_engine=None, start_time=time.time(), scan_count_ref=MagicMock())


def _make_scan_request(command=None):
    req = type("Req", (), {})()
    req.command = command or ["echo", "hello"]
    req.policy = ""
    req.timeout = 30.0
    req.cwd = ""
    return req


def _audit_events():
    return audit_logger_mod._audit_logger.query(limit=1000)


class TestGrpcScanAuditTenancy:
    """WO7.0.0-003: gRPC Scan audit events carry tenant_id + token-derived actor."""

    def test_scan_audit_has_tenant_id_metadata(self):
        _setup_tenants()
        servicer = _make_servicer()
        servicer.Scan(_make_scan_request(), _ctx(TOKEN_ALPHA))

        events = _audit_events()
        scan_events = [e for e in events if e.event_type in (AuditEventType.SCAN_START, AuditEventType.SCAN_COMPLETE)]
        assert len(scan_events) >= 1, "expected at least one scan audit event"
        for e in scan_events:
            assert e.metadata.get("tenant_id") == "alpha", f"tenant_id missing or wrong: {e.metadata}"

    def test_scan_audit_actor_is_token_hash_not_hardcoded(self):
        _setup_tenants()
        servicer = _make_servicer()
        servicer.Scan(_make_scan_request(), _ctx(TOKEN_ALPHA))

        events = _audit_events()
        scan_events = [e for e in events if e.event_type == AuditEventType.SCAN_START]
        assert scan_events, "no SCAN_START event"
        assert scan_events[0].actor == _actor(TOKEN_ALPHA), (
            f"actor should be token hash prefix, got {scan_events[0].actor!r}"
        )
        assert scan_events[0].actor != "picodome-grpc", "actor is still the hardcoded literal"

    def test_tenant_a_scan_invisible_to_tenant_b(self):
        _setup_tenants()
        servicer = _make_servicer()
        servicer.Scan(_make_scan_request(), _ctx(TOKEN_ALPHA))

        events = _audit_events()
        # Tenant B sees only events with tenant_id == "beta" — none of alpha's
        beta_events = [e for e in events if e.metadata.get("tenant_id") == "beta"]
        assert beta_events == [], "tenant B should not see tenant A's scan audit events"

        # Tenant A sees its own scan events
        alpha_events = [e for e in events if e.metadata.get("tenant_id") == "alpha"]
        assert alpha_events, "tenant A should see its own scan audit events"

    def test_two_tenants_each_see_own_events(self):
        _setup_tenants()
        servicer = _make_servicer()
        servicer.Scan(_make_scan_request(["echo", "a"]), _ctx(TOKEN_ALPHA))
        servicer.Scan(_make_scan_request(["echo", "b"]), _ctx(TOKEN_BETA))

        events = _audit_events()
        alpha_events = [e for e in events if e.metadata.get("tenant_id") == "alpha"]
        beta_events = [e for e in events if e.metadata.get("tenant_id") == "beta"]
        assert alpha_events, "alpha should have scan audit events"
        assert beta_events, "beta should have scan audit events"
        assert all(e.actor == _actor(TOKEN_ALPHA) for e in alpha_events)
        assert all(e.actor == _actor(TOKEN_BETA) for e in beta_events)

    def test_no_context_falls_back_to_hardcoded_actor(self):
        """When context is None (dev/legacy), the actor stays picodome-grpc
        and metadata is empty — backwards compatible."""
        servicer = _make_servicer()
        servicer._audit_log("SCAN_START", detail="legacy")
        events = _audit_events()
        assert events
        assert events[0].actor == "picodome-grpc"
        assert events[0].metadata == {}
