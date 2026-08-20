from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

from picosentry.sandbox.tenant import DEFAULT_TENANT, TenantId

if TYPE_CHECKING:
    from picosentry.sandbox.daemon.store import PersistentScanJobStore

logger = logging.getLogger("picodome.tenant.store")


def _job_tenant(job: dict[str, Any]) -> str:
    """Effective tenant of a stored job (WO5.0.0-001): sqlite pre-tenancy
    rows carry tenant_id as NULL (key present, value None) — and empty-string
    writes — so `.get(key, default)` never applies the default. Truthiness
    check normalizes both to DEFAULT_TENANT."""
    return job.get("tenant_id") or DEFAULT_TENANT.normalized


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

        job_tenant = _job_tenant(job)
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
        # WO6.0.0-018: the inner scan used a hardcoded 1000 with no ceiling
        # note. Pull enough to satisfy `limit` after the tenant filter, with
        # a sane cap so a malicious `limit` doesn't scan the whole store.
        # ponytail: ceiling — this over-fetches by the cross-tenant ratio;
        # push the tenant filter into the store layer for true bound.
        inner_limit = max(limit, 1) * 4
        if inner_limit > 4000:
            inner_limit = 4000
        all_jobs = self._store.list_recent(limit=inner_limit)
        tenant_jobs = [j for j in all_jobs if _job_tenant(j) == tid.normalized]
        return tenant_jobs[:limit]

    @property
    def store(self) -> PersistentScanJobStore:
        return self._store
