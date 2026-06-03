"""Tests for tenant-aware scan job store — B09.

Covers:
- Adding jobs with tenant_id tag
- Getting jobs filtered by tenant (cross-tenant denied)
- Updating jobs with tenant check
- Listing recent jobs filtered by tenant
- Default tenant fallback
"""

from __future__ import annotations

import pytest

from picosentry.sandbox.daemon.store import PersistentScanJobStore
from picosentry.sandbox.tenant import TenantId
from picosentry.sandbox.tenant.store import TenantAwareScanJobStore


@pytest.fixture
def tenant_store(tmp_path):
    """Create a tenant-aware store backed by a PersistentScanJobStore."""
    backing = PersistentScanJobStore(store_dir=tmp_path)
    return TenantAwareScanJobStore(store=backing)


class TestTenantAwareAdd:
    def test_add_tags_tenant_id(self, tenant_store):
        job = tenant_store.add("job-1", ["ls"], "alice", tenant_id=TenantId("alpha"))
        assert job["tenant_id"] == "alpha"

    def test_add_default_tenant(self, tenant_store):
        job = tenant_store.add("job-2", ["ls"], "alice")
        assert job["tenant_id"] == "default"

    def test_add_custom_default_tenant(self, tmp_path):
        backing = PersistentScanJobStore(store_dir=tmp_path)
        store = TenantAwareScanJobStore(store=backing, default_tenant=TenantId("beta"))
        job = store.add("job-3", ["ls"], "alice")
        assert job["tenant_id"] == "beta"


class TestTenantAwareGet:
    def test_get_own_job(self, tenant_store):
        tenant_store.add("job-1", ["ls"], "alice", tenant_id=TenantId("alpha"))
        job = tenant_store.get("job-1", tenant_id=TenantId("alpha"))
        assert job is not None
        assert job["job_id"] == "job-1"

    def test_get_cross_tenant_denied(self, tenant_store):
        tenant_store.add("job-1", ["ls"], "alice", tenant_id=TenantId("alpha"))
        job = tenant_store.get("job-1", tenant_id=TenantId("beta"))
        assert job is None

    def test_get_default_tenant(self, tenant_store):
        tenant_store.add("job-2", ["ls"], "alice")
        job = tenant_store.get("job-2")
        assert job is not None

    def test_get_nonexistent(self, tenant_store):
        job = tenant_store.get("no-such-job", tenant_id=TenantId("alpha"))
        assert job is None


class TestTenantAwareUpdate:
    def test_update_own_job(self, tenant_store):
        tenant_store.add("job-1", ["ls"], "alice", tenant_id=TenantId("alpha"))
        result = tenant_store.update("job-1", tenant_id=TenantId("alpha"), status="completed")
        assert result is not None
        assert result["status"] == "completed"

    def test_update_cross_tenant_denied(self, tenant_store):
        tenant_store.add("job-1", ["ls"], "alice", tenant_id=TenantId("alpha"))
        result = tenant_store.update("job-1", tenant_id=TenantId("beta"), status="completed")
        assert result is None

    def test_update_nonexistent(self, tenant_store):
        result = tenant_store.update("no-such-job", tenant_id=TenantId("alpha"), status="completed")
        assert result is None


class TestTenantAwareListRecent:
    def test_list_only_own_tenant(self, tenant_store):
        tenant_store.add("job-1", ["ls"], "alice", tenant_id=TenantId("alpha"))
        tenant_store.add("job-2", ["cat"], "bob", tenant_id=TenantId("beta"))
        tenant_store.add("job-3", ["pwd"], "alice", tenant_id=TenantId("alpha"))

        alpha_jobs = tenant_store.list_recent(tenant_id=TenantId("alpha"))
        assert len(alpha_jobs) == 2
        assert all(j["tenant_id"] == "alpha" for j in alpha_jobs)

    def test_list_respects_limit(self, tenant_store):
        for i in range(10):
            tenant_store.add(f"job-{i}", ["ls"], "alice", tenant_id=TenantId("alpha"))

        jobs = tenant_store.list_recent(tenant_id=TenantId("alpha"), limit=3)
        assert len(jobs) == 3

    def test_list_default_tenant(self, tenant_store):
        tenant_store.add("job-1", ["ls"], "alice")
        jobs = tenant_store.list_recent()
        assert len(jobs) == 1
        assert jobs[0]["tenant_id"] == "default"

    def test_list_empty_for_tenant(self, tenant_store):
        tenant_store.add("job-1", ["ls"], "alice", tenant_id=TenantId("alpha"))
        jobs = tenant_store.list_recent(tenant_id=TenantId("beta"))
        assert len(jobs) == 0


class TestTenantIsolation:
    def test_full_isolation_scenario(self, tenant_store):
        """End-to-end: two tenants, complete isolation."""
        alpha = TenantId("alpha")
        beta = TenantId("beta")

        # Alpha creates jobs
        tenant_store.add("a-1", ["ls"], "alice", tenant_id=alpha)
        tenant_store.add("a-2", ["cat"], "alice", tenant_id=alpha)

        # Beta creates jobs
        tenant_store.add("b-1", ["rm"], "bob", tenant_id=beta)

        # Alpha can see only 2 jobs
        alpha_jobs = tenant_store.list_recent(tenant_id=alpha)
        assert len(alpha_jobs) == 2

        # Beta can see only 1 job
        beta_jobs = tenant_store.list_recent(tenant_id=beta)
        assert len(beta_jobs) == 1

        # Alpha cannot access Beta's job
        assert tenant_store.get("b-1", tenant_id=alpha) is None

        # Beta cannot access Alpha's job
        assert tenant_store.get("a-1", tenant_id=beta) is None

        # Alpha cannot update Beta's job
        assert tenant_store.update("b-1", tenant_id=alpha, status="completed") is None

        # Beta CAN update their own job
        result = tenant_store.update("b-1", tenant_id=beta, status="completed")
        assert result is not None
        assert result["status"] == "completed"
