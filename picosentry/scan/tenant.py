"""
Multi-tenant isolation for enterprise PicoSentry deployments.

Provides tenant-scoped data isolation, access boundaries, and resource
management for shared PicoSentry infrastructure.

Tenants are isolated via:
- Separate data directories for audit, corpus, policy, and IoC data
- Tenant-scoped audit sinks with per-tenant log files
- Tenant-scoped cache with isolated key namespaces
- Tenant policy stacks with inheritance boundaries

Usage:
    from picosentry.scan.tenant import TenantManager, TenantConfig

    manager = TenantManager(base_dir=Path("/var/lib/picosentry/tenants"))
    manager.create_tenant("org-alpha", display_name="Alpha Corp")
    manager.create_tenant("org-beta", display_name="Beta Inc")

    # Get tenant-scoped paths
    alpha = manager.get_tenant("org-alpha")
    print(alpha.audit_dir)   # /var/lib/picosentry/tenants/org-alpha/audit
    print(alpha.corpus_dir)  # /var/lib/picosentry/tenants/org-alpha/corpus
"""

from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from picosentry.scan.audit import audit

logger = logging.getLogger("picosentry.tenant")

TENANT_VERSION = "1.0"


# ── Tenant configuration ─────────────────────────────────────────────────


@dataclass
class TenantConfig:
    """Configuration for a single tenant.

    Each tenant gets its own data directory structure:
        <base_dir>/<tenant_id>/audit/
        <base_dir>/<tenant_id>/corpus/
        <base_dir>/<tenant_id>/policy/
        <base_dir>/<tenant_id>/ioc/
        <base_dir>/<tenant_id>/cache/
    """

    tenant_id: str = ""
    display_name: str = ""
    created_at: str = ""
    created_by: str = ""
    enabled: bool = True
    plan: str = "standard"  # standard, enterprise
    max_scans_per_day: int = 0  # 0 = unlimited
    max_targets: int = 0  # 0 = unlimited
    rbac_scopes: list[str] = field(default_factory=lambda: ["read", "scan"])
    metadata: dict[str, Any] = field(default_factory=dict)

    # Paths (set by TenantManager)
    base_path: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    @property
    def audit_dir(self) -> Path:
        return Path(self.base_path) / "audit" if self.base_path else Path()

    @property
    def corpus_dir(self) -> Path:
        return Path(self.base_path) / "corpus" if self.base_path else Path()

    @property
    def policy_dir(self) -> Path:
        return Path(self.base_path) / "policy" if self.base_path else Path()

    @property
    def ioc_dir(self) -> Path:
        return Path(self.base_path) / "ioc" if self.base_path else Path()

    @property
    def cache_dir(self) -> Path:
        return Path(self.base_path) / "cache" if self.base_path else Path()

    @property
    def config_path(self) -> Path:
        return Path(self.base_path) / "tenant.json" if self.base_path else Path()

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "display_name": self.display_name,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "enabled": self.enabled,
            "plan": self.plan,
            "max_scans_per_day": self.max_scans_per_day,
            "max_targets": self.max_targets,
            "rbac_scopes": self.rbac_scopes,
            "metadata": self.metadata,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> TenantConfig:
        return TenantConfig(
            tenant_id=d.get("tenant_id", ""),
            display_name=d.get("display_name", ""),
            created_at=d.get("created_at", ""),
            created_by=d.get("created_by", ""),
            enabled=d.get("enabled", True),
            plan=d.get("plan", "standard"),
            max_scans_per_day=d.get("max_scans_per_day", 0),
            max_targets=d.get("max_targets", 0),
            rbac_scopes=d.get("rbac_scopes", ["read", "scan"]),
            metadata=d.get("metadata", {}),
        )


# ── Tenant manager ──────────────────────────────────────────────────────


class TenantManager:
    """Multi-tenant manager for PicoSentry deployments.

    Manages tenant lifecycle, data isolation, and access boundaries.
    Each tenant's data is stored in a separate directory tree.
    """

    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = base_dir or Path.home() / ".local" / "share" / "picosentry" / "tenants"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._tenants: dict[str, TenantConfig] = {}
        self._load_state()

    def _tenants_file(self) -> Path:
        return self.base_dir / "tenants.json"

    def _load_state(self) -> None:
        tenants_file = self._tenants_file()
        if not tenants_file.is_file():
            return
        try:
            data = json.loads(tenants_file.read_text(encoding="utf-8"))
            for tid, td in data.get("tenants", {}).items():
                config = TenantConfig.from_dict(td)
                config.base_path = str(self.base_dir / tid)
                self._tenants[tid] = config
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load tenants state: %s", e)

    def _save_state(self) -> None:
        tenants_file = self._tenants_file()
        data = {
            "tenants": {tid: t.to_dict() for tid, t in self._tenants.items()},
            "version": TENANT_VERSION,
        }
        tenants_file.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    # ── Tenant lifecycle ──────────────────────────────────────────────

    def create_tenant(
        self,
        tenant_id: str,
        display_name: str = "",
        plan: str = "standard",
        created_by: str = "",
        rbac_scopes: list[str] | None = None,
        max_scans_per_day: int = 0,
        max_targets: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> TenantConfig:
        """Create a new tenant with isolated data directories.

        Args:
            tenant_id: Unique tenant identifier (alphanumeric + hyphens).
            display_name: Human-readable name.
            plan: Subscription plan (standard, enterprise).
            created_by: Identity creating the tenant.
            rbac_scopes: Default RBAC scopes for tenant members.
            max_scans_per_day: Rate limit (0 = unlimited).
            max_targets: Maximum targets (0 = unlimited).
            metadata: Additional tenant metadata.

        Returns:
            TenantConfig with paths initialized.

        Raises:
            ValueError: If tenant_id already exists or is invalid.
        """
        import re

        if not re.match(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$", tenant_id):
            raise ValueError(f"Invalid tenant_id '{tenant_id}': must be 3-64 chars, lowercase alphanumeric + hyphens")

        if tenant_id in self._tenants:
            raise ValueError(f"Tenant '{tenant_id}' already exists")

        config = TenantConfig(
            tenant_id=tenant_id,
            display_name=display_name or tenant_id,
            plan=plan,
            created_by=created_by,
            rbac_scopes=rbac_scopes or ["read", "scan"],
            max_scans_per_day=max_scans_per_day,
            max_targets=max_targets,
            metadata=metadata or {},
        )

        # Create tenant directory structure
        tenant_dir = self.base_dir / tenant_id
        tenant_dir.mkdir(parents=True, exist_ok=True)
        config.base_path = str(tenant_dir)

        # Create sub-directories
        for subdir in ("audit", "corpus", "policy", "ioc", "cache"):
            (tenant_dir / subdir).mkdir(exist_ok=True)

        # Write tenant config
        config.config_path.write_text(json.dumps(config.to_dict(), indent=2), encoding="utf-8")

        self._tenants[tenant_id] = config
        self._save_state()

        audit(
            "tenant.create",
            target=tenant_id,
            metadata={"plan": plan, "display_name": display_name},
        )

        return config

    def get_tenant(self, tenant_id: str) -> TenantConfig | None:
        """Get a tenant's configuration."""
        return self._tenants.get(tenant_id)

    def update_tenant(self, tenant_id: str, **kwargs: Any) -> TenantConfig:
        """Update a tenant's configuration.

        Args:
            tenant_id: Tenant to update.
            **kwargs: Fields to update (display_name, plan, enabled, etc.)

        Returns:
            Updated TenantConfig.

        Raises:
            ValueError: If tenant not found.
        """
        if tenant_id not in self._tenants:
            raise ValueError(f"Tenant '{tenant_id}' not found")

        config = self._tenants[tenant_id]
        for key, value in kwargs.items():
            if hasattr(config, key) and key != "tenant_id" and key != "base_path":
                setattr(config, key, value)

        # Write updated config
        config.config_path.write_text(json.dumps(config.to_dict(), indent=2), encoding="utf-8")
        self._save_state()

        audit("tenant.update", target=tenant_id, metadata={"fields": list(kwargs.keys())})

        return config

    def delete_tenant(self, tenant_id: str, confirm: bool = False) -> bool:
        """Delete a tenant and all its data.

        Args:
            tenant_id: Tenant to delete.
            confirm: Must be True to actually delete.

        Returns:
            True if tenant was deleted.

        Raises:
            ValueError: If confirm is False or tenant not found.
        """
        if not confirm:
            raise ValueError("Pass confirm=True to delete a tenant and all its data")

        if tenant_id not in self._tenants:
            audit("tenant.delete", target=tenant_id, outcome="not_found")
            return False

        config = self._tenants[tenant_id]
        tenant_dir = Path(config.base_path)

        # Remove data directory
        if tenant_dir.is_dir():
            shutil.rmtree(tenant_dir)

        del self._tenants[tenant_id]
        self._save_state()

        audit("tenant.delete", target=tenant_id, outcome="success")

        return True

    def list_tenants(self, enabled_only: bool = False) -> list[TenantConfig]:
        """List all tenants, optionally filtering to enabled only."""
        tenants = list(self._tenants.values())
        if enabled_only:
            tenants = [t for t in tenants if t.enabled]
        return sorted(tenants, key=lambda t: t.tenant_id)

    def disable_tenant(self, tenant_id: str) -> TenantConfig:
        """Disable a tenant (stops scanning but preserves data)."""
        return self.update_tenant(tenant_id, enabled=False)

    def enable_tenant(self, tenant_id: str) -> TenantConfig:
        """Re-enable a disabled tenant."""
        return self.update_tenant(tenant_id, enabled=True)

    # ── Tenant-scoped paths ────────────────────────────────────────────

    def tenant_audit_path(self, tenant_id: str, filename: str = "audit.jsonl") -> Path | None:
        """Get the audit log path for a tenant."""
        config = self._tenants.get(tenant_id)
        if not config:
            return None
        return config.audit_dir / filename

    def tenant_corpus_path(self, tenant_id: str) -> Path | None:
        """Get the corpus directory for a tenant."""
        config = self._tenants.get(tenant_id)
        if not config:
            return None
        return config.corpus_dir

    def tenant_policy_path(self, tenant_id: str, filename: str = ".picosentry-policy.yml") -> Path | None:
        """Get the policy file path for a tenant."""
        config = self._tenants.get(tenant_id)
        if not config:
            return None
        return config.policy_dir / filename

    def tenant_ioc_path(self, tenant_id: str) -> Path | None:
        """Get the IoC directory for a tenant."""
        config = self._tenants.get(tenant_id)
        if not config:
            return None
        return config.ioc_dir

    def tenant_cache_path(self, tenant_id: str) -> Path | None:
        """Get the cache directory for a tenant."""
        config = self._tenants.get(tenant_id)
        if not config:
            return None
        return config.cache_dir

    # ── Tenant health ──────────────────────────────────────────────────

    def tenant_health(self, tenant_id: str) -> dict[str, Any]:
        """Get health status for a tenant.

        Checks data directories, policy presence, and corpus status.
        """
        config = self._tenants.get(tenant_id)
        if not config:
            return {"tenant_id": tenant_id, "status": "not_found"}

        tenant_dir = Path(config.base_path)
        policy_dir = config.policy_dir
        corpus_dir = config.corpus_dir
        audit_dir = config.audit_dir

        # Check directory existence
        dirs_ok = tenant_dir.is_dir()

        # Check policy
        policy_file = policy_dir / ".picosentry-policy.yml"
        has_policy = policy_file.is_file()

        # Check audit log
        has_audit = any(audit_dir.glob("*.jsonl"))

        # Check corpus
        has_corpus = any(corpus_dir.glob("*.json"))

        # Check IoC data
        has_ioc = any((config.ioc_dir).glob("*.json"))

        # Compute disk usage
        disk_usage = sum(f.stat().st_size for f in tenant_dir.rglob("*") if f.is_file()) if dirs_ok else 0

        return {
            "tenant_id": tenant_id,
            "status": "healthy" if dirs_ok and config.enabled else ("disabled" if not config.enabled else "degraded"),
            "enabled": config.enabled,
            "plan": config.plan,
            "display_name": config.display_name,
            "directories_ok": dirs_ok,
            "has_policy": has_policy,
            "has_audit_log": has_audit,
            "has_corpus": has_corpus,
            "has_ioc": has_ioc,
            "disk_usage_bytes": disk_usage,
            "max_scans_per_day": config.max_scans_per_day,
            "max_targets": config.max_targets,
        }

    def fleet_overview(self) -> dict[str, Any]:
        """Get an overview of all tenants.

        Returns summary stats: total tenants, enabled, disabled,
        disk usage, and per-tenant health.
        """
        tenant_healths = {tid: self.tenant_health(tid) for tid in self._tenants}
        total = len(self._tenants)
        enabled = sum(1 for t in self._tenants.values() if t.enabled)
        healthy = sum(1 for h in tenant_healths.values() if h["status"] == "healthy")
        total_disk = sum(h.get("disk_usage_bytes", 0) for h in tenant_healths.values())

        return {
            "total_tenants": total,
            "enabled_tenants": enabled,
            "disabled_tenants": total - enabled,
            "healthy_tenants": healthy,
            "degraded_tenants": total - healthy,
            "total_disk_usage_bytes": total_disk,
            "tenants": tenant_healths,
        }
