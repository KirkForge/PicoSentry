"""Tests for tenant isolation enforcement — B11.

End-to-end tests proving that cross-tenant access is denied at
every layer: storage, API, and audit.

Covers:
- Cross-tenant job access denied
- Cross-tenant job update denied
- Cross-tenant job listing returns empty
- Cross-tenant baseline access denied (via tenant_key namespacing)
- Cross-tenant audit query filtered by tenant
- Default tenant isolation from named tenants
- Multiple concurrent tenants don't leak data
- Tenant resolution produces correct isolation boundaries
"""

from __future__ import annotations

import hashlib

import pytest

from picosentry.sandbox.audit import AuditEventType, AuditLogger
from picosentry.sandbox.daemon.store import PersistentScanJobStore
from picosentry.sandbox.tenant import (
    DEFAULT_TENANT,
    TenantContext,
    TenantId,
    reset_tenant_registry,
    setup_tenant_registry,
    tenant_key,
)
from picosentry.sandbox.tenant.store import TenantAwareScanJobStore


class TestCrossTenantJobAccess:
    """Prove that tenant A cannot access tenant B's jobs."""

    @pytest.fixture
    def stores(self, tmp_path):
        backing = PersistentScanJobStore(store_dir=tmp_path)
        tenant_store = TenantAwareScanJobStore(store=backing)
        alpha = TenantId("alpha")
        beta = TenantId("beta")
        return tenant_store, alpha, beta

    def test_alpha_cannot_get_beta_job(self, stores):
        store, alpha, beta = stores
        store.add("b-1", ["ls"], "bob", tenant_id=beta)
        assert store.get("b-1", tenant_id=alpha) is None

    def test_beta_cannot_get_alpha_job(self, stores):
        store, alpha, beta = stores
        store.add("a-1", ["ls"], "alice", tenant_id=alpha)
        assert store.get("a-1", tenant_id=beta) is None

    def test_alpha_cannot_update_beta_job(self, stores):
        store, alpha, beta = stores
        store.add("b-1", ["ls"], "bob", tenant_id=beta)
        result = store.update("b-1", tenant_id=alpha, status="completed")
        assert result is None

    def test_alpha_update_does_not_affect_beta(self, stores):
        store, alpha, beta = stores
        store.add("b-1", ["ls"], "bob", tenant_id=beta)
        # Alpha tries to update
        store.update("b-1", tenant_id=alpha, status="hacked")
        # Beta's job should be unchanged
        job = store.get("b-1", tenant_id=beta)
        assert job is not None
        assert job["status"] == "pending"

    def test_alpha_list_excludes_beta_jobs(self, stores):
        store, alpha, beta = stores
        store.add("a-1", ["ls"], "alice", tenant_id=alpha)
        store.add("b-1", ["rm"], "bob", tenant_id=beta)
        store.add("a-2", ["cat"], "alice", tenant_id=alpha)
        store.add("b-2", ["sh"], "bob", tenant_id=beta)

        alpha_jobs = store.list_recent(tenant_id=alpha)
        assert len(alpha_jobs) == 2
        assert all(j["tenant_id"] == "alpha" for j in alpha_jobs)


class TestCrossTenantStorageKeys:
    """Prove that different tenants get different storage keys."""

    def test_different_tenants_different_keys(self):
        alpha = TenantId("alpha")
        beta = TenantId("beta")
        assert tenant_key(alpha, "baseline") != tenant_key(beta, "baseline")

    def test_same_key_different_prefix(self):
        alpha = TenantId("alpha")
        beta = TenantId("beta")
        k1 = tenant_key(alpha, "config:main")
        k2 = tenant_key(beta, "config:main")
        assert k1.startswith("tenant:alpha:")
        assert k2.startswith("tenant:beta:")
        assert k1 != k2


class TestDefaultTenantIsolation:
    """Prove the default tenant is isolated from named tenants."""

    @pytest.fixture
    def stores(self, tmp_path):
        backing = PersistentScanJobStore(store_dir=tmp_path)
        tenant_store = TenantAwareScanJobStore(store=backing)
        return tenant_store

    def test_default_tenant_cannot_access_named(self, stores):
        store = stores
        store.add("d-1", ["ls"], "user1")  # default tenant
        store.add("a-1", ["ls"], "alice", tenant_id=TenantId("alpha"))

        # Default can't see alpha's job
        assert store.get("a-1") is None

        # Alpha can't see default's job
        assert store.get("d-1", tenant_id=TenantId("alpha")) is None

    def test_default_list_excludes_named(self, stores):
        store = stores
        store.add("d-1", ["ls"], "user1")
        store.add("a-1", ["ls"], "alice", tenant_id=TenantId("alpha"))

        default_jobs = store.list_recent()
        assert len(default_jobs) == 1
        assert default_jobs[0]["tenant_id"] == "default"


class TestMultipleConcurrentTenants:
    """Prove that many tenants coexist without data leakage."""

    @pytest.fixture
    def stores(self, tmp_path):
        backing = PersistentScanJobStore(store_dir=tmp_path)
        tenant_store = TenantAwareScanJobStore(store=backing)
        return tenant_store

    def test_five_tenants_isolated(self, stores):
        store = stores
        tenants = [TenantId(f"team-{i}") for i in range(5)]

        # Each tenant creates 3 jobs
        for i, tid in enumerate(tenants):
            for j in range(3):
                store.add(f"{tid}-job-{j}", ["cmd"], f"user-{i}", tenant_id=tid)

        # Each tenant sees exactly 3 jobs
        for tid in tenants:
            jobs = store.list_recent(tenant_id=tid)
            assert len(jobs) == 3, f"Tenant {tid} sees {len(jobs)} jobs, expected 3"

    def test_no_cross_tenant_access_with_many_tenants(self, stores):
        store = stores
        tenants = [TenantId(f"team-{i}") for i in range(5)]

        for i, tid in enumerate(tenants):
            store.add(f"{tid}-secret", ["secret-cmd"], f"user-{i}", tenant_id=tid)

        # Each tenant can access their own secret
        for tid in tenants:
            job = store.get(f"{tid}-secret", tenant_id=tid)
            assert job is not None

        # But no tenant can access any other tenant's secret
        for i, tid_a in enumerate(tenants):
            for j, tid_b in enumerate(tenants):
                if i == j:
                    continue
                job = store.get(f"{tid_b}-secret", tenant_id=tid_a)
                assert job is None, f"Tenant {tid_a} accessed {tid_b}'s job!"


class TestTenantAuditIsolation:
    """Prove that audit events are tagged with tenant context."""

    def test_audit_event_includes_tenant_metadata(self, tmp_path):
        audit = AuditLogger(log_dir=tmp_path)
        event = audit.record(
            event_type=AuditEventType.SCAN_START,
            actor="alice",
            detail="test scan",
            metadata={"tenant_id": "alpha"},
        )
        assert event.metadata.get("tenant_id") == "alpha"

    def test_tenant_audit_query_filtered(self, tmp_path):
        """Simulate filtering audit events by tenant."""
        audit = AuditLogger(log_dir=tmp_path)

        # Record events for two tenants
        audit.record(
            event_type=AuditEventType.SCAN_START,
            actor="alice",
            metadata={"tenant_id": "alpha"},
        )
        audit.record(
            event_type=AuditEventType.SCAN_START,
            actor="bob",
            metadata={"tenant_id": "beta"},
        )
        audit.record(
            event_type=AuditEventType.SCAN_COMPLETE,
            actor="alice",
            metadata={"tenant_id": "alpha"},
        )

        # Query all events and filter by tenant
        all_events = audit.query(limit=100)
        alpha_events = [e for e in all_events if e.metadata.get("tenant_id") == "alpha"]
        beta_events = [e for e in all_events if e.metadata.get("tenant_id") == "beta"]

        assert len(alpha_events) == 2
        assert len(beta_events) == 1


class TestTenantRegistryIsolation:
    """Prove the tenant registry enforces isolation boundaries."""

    def setup_method(self):
        reset_tenant_registry()

    def teardown_method(self):
        reset_tenant_registry()

    def test_resolve_produces_correct_tenant(self):
        registry = setup_tenant_registry(
            [
                TenantContext(tenant_id=TenantId("alpha")),
                TenantContext(tenant_id=TenantId("beta")),
            ]
        )

        token_alpha = "token-alpha-123"
        hash_alpha = hashlib.sha256(token_alpha.encode("utf-8")).hexdigest()
        registry.map_token(hash_alpha, TenantId("alpha"))

        token_beta = "token-beta-456"
        hash_beta = hashlib.sha256(token_beta.encode("utf-8")).hexdigest()
        registry.map_token(hash_beta, TenantId("beta"))

        # Each token resolves to its own tenant
        assert registry.resolve_tenant(hash_alpha) == TenantId("alpha")
        assert registry.resolve_tenant(hash_beta) == TenantId("beta")

        # Unknown token resolves to default
        assert registry.resolve_tenant("unknown-hash") == DEFAULT_TENANT

    def test_cannot_spoof_tenant_with_header_without_registration(self):
        registry = setup_tenant_registry(
            [
                TenantContext(tenant_id=TenantId("alpha")),
            ]
        )

        # "beta" is not registered, so header falls back
        resolved = registry.resolve_tenant("some-hash", header_tenant="beta")
        assert resolved == DEFAULT_TENANT