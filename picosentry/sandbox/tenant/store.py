"""Tenant-aware scan job store — wraps PersistentScanJobStore with tenant isolation.

Each job is tagged with a tenant_id. Queries are filtered to return only
the requesting tenant's jobs. Cross-tenant access returns None / empty.

The underlying storage is shared (same JSONL file), but the tenant_id
field in each job record enforces isolation at the application layer.
For stricter isolation, use separate storage directories per tenant.
"""

from __future__ import annotations

import logging
from typing import Any

from picosentry.sandbox.daemon.store import PersistentScanJobStore
from picosentry.sandbox.tenant import DEFAULT_TENANT, TenantId

logger = logging.getLogger("picodome.tenant.store")


class TenantAwareScanJobStore:
    """Scan job store with per-tenant isolation.

    Wraps PersistentScanJobStore and ensures:
      - Every job is tagged with the caller's tenant_id
      - Queries only return jobs belonging to the caller's tenant
      - Cross-tenant access is denied (returns None / empty)

    Args:
        store: The underlying PersistentScanJobStore.
        default_tenant: Tenant to use when none is specified.
    """

    def __init__(
        self,
        store: PersistentScanJobStore,
        default_tenant: TenantId | None = None,
    ) -> None:
        self._store = store
        self._default_tenant = default_tenant or DEFAULT_TENANT

    def add(
        self,
        job_id: str,
        command: list[str],
        actor: str,
        tenant_id: TenantId | None = None,
    ) -> dict[str, Any]:
        """Add a job tagged with the tenant's ID.

        Args:
            job_id: Unique job identifier.
            command: Command that was submitted.
            actor: Authenticated actor.
            tenant_id: Tenant identity (defaults to default tenant).

        Returns:
            The job dict (with tenant_id field).
        """
        tid = tenant_id or self._default_tenant
        job = self._store.add(job_id, command, actor)
        # Tag the job with tenant_id
        job["tenant_id"] = tid.normalized
        self._store.update(job_id, tenant_id=tid.normalized)
        return job

    def get(
        self,
        job_id: str,
        tenant_id: TenantId | None = None,
    ) -> dict[str, Any] | None:
        """Get a job by ID, only if it belongs to the requesting tenant.

        Returns:
            The job dict, or None if not found or wrong tenant.
        """
        tid = tenant_id or self._default_tenant
        job = self._store.get(job_id)
        if job is None:
            return None
        # Check tenant ownership
        job_tenant = job.get("tenant_id", DEFAULT_TENANT.normalized)
        if job_tenant != tid.normalized:
            logger.warning(
                "Cross-tenant access denied: tenant=%s tried to access job %s (owner=%s)",
                tid,
                job_id[:8],
                job_tenant,
            )
            return None
        return job

    def update(
        self,
        job_id: str,
        tenant_id: TenantId | None = None,
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        """Update a job, only if it belongs to the requesting tenant.

        Returns:
            Updated job dict, or None if not found or wrong tenant.
        """
        tid = tenant_id or self._default_tenant
        # Verify ownership first
        job = self.get(job_id, tenant_id=tid)
        if job is None:
            return None
        return self._store.update(job_id, **kwargs)

    def list_recent(
        self,
        tenant_id: TenantId | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List recent jobs for a specific tenant only.

        Returns:
            List of job dicts belonging to the requesting tenant.
        """
        tid = tenant_id or self._default_tenant
        all_jobs = self._store.list_recent(limit=1000)  # get plenty, then filter
        tenant_jobs = [j for j in all_jobs if j.get("tenant_id", DEFAULT_TENANT.normalized) == tid.normalized]
        return tenant_jobs[:limit]

    @property
    def store(self) -> PersistentScanJobStore:
        """Access the underlying store (for admin operations)."""
        return self._store
