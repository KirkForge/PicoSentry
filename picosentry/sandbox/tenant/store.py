from __future__ import annotations

import logging
from typing import Any

from picosentry.sandbox.daemon.store import PersistentScanJobStore
from picosentry.sandbox.tenant import DEFAULT_TENANT, TenantId

logger = logging.getLogger("picodome.tenant.store")


class TenantAwareScanJobStore:
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
        tid = tenant_id or self._default_tenant
        job = self._store.add(job_id, command, actor)

        job["tenant_id"] = tid.normalized
        self._store.update(job_id, tenant_id=tid.normalized)
        return job

    def get(
        self,
        job_id: str,
        tenant_id: TenantId | None = None,
    ) -> dict[str, Any] | None:
        tid = tenant_id or self._default_tenant
        job = self._store.get(job_id)
        if job is None:
            return None

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
        tid = tenant_id or self._default_tenant

        job = self.get(job_id, tenant_id=tid)
        if job is None:
            return None
        return self._store.update(job_id, **kwargs)

    def list_recent(
        self,
        tenant_id: TenantId | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        tid = tenant_id or self._default_tenant
        all_jobs = self._store.list_recent(limit=1000)  # get plenty, then filter
        tenant_jobs = [j for j in all_jobs if j.get("tenant_id", DEFAULT_TENANT.normalized) == tid.normalized]
        return tenant_jobs[:limit]

    @property
    def store(self) -> PersistentScanJobStore:
        return self._store
