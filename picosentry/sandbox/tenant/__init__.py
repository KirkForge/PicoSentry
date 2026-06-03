"""Multi-tenant isolation for PicoDome.

In enterprise deployments, a single PicoDome instance serves multiple
teams within a company. Each team's data is namespaced by TenantId
and isolated at the storage, API, and audit layers.

Tenant resolution:
  1. X-Tenant HTTP header on API requests
  2. Token-to-tenant mapping (configured by admin)
  3. Default tenant (single-tenant mode when no mapping exists)

Design:
  - TenantId is an opaque string (e.g. "team-platform", "org-security")
  - All storage keys are prefixed with tenant_id
  - Cross-tenant access is denied at the API layer
  - Audit events include tenant context
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("picodome.tenant")

# ─── Tenant identity ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TenantId:
    """Immutable tenant identifier.

    A TenantId is a short, unique string that namespaces all data
    belonging to a team or organization within a shared PicoDome instance.
    """

    value: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("TenantId cannot be empty")
        # Normalize: lowercase, strip whitespace
        normalized = self.value.strip().lower()
        # Validate: alphanumeric + hyphens + underscores only
        if not all(c.isalnum() or c in "-_" for c in normalized):
            raise ValueError(
                f"TenantId '{self.value}' contains invalid characters. Use only alphanumeric, hyphens, and underscores."
            )

    @property
    def normalized(self) -> str:
        """Normalized tenant ID (lowercase, stripped)."""
        return self.value.strip().lower()

    def __str__(self) -> str:
        return self.normalized

    def __hash__(self) -> int:
        return hash(self.normalized)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TenantId):
            return self.normalized == other.normalized
        if isinstance(other, str):
            return self.normalized == other.strip().lower()
        return NotImplemented


# Sentinel for "no tenant" / single-tenant mode
DEFAULT_TENANT = TenantId("default")


@dataclass(frozen=True)
class TenantContext:
    """Full tenant context carried through a request lifecycle.

    Includes the tenant ID, display name, and any metadata
    (quota limits, feature flags, etc.).
    """

    tenant_id: TenantId
    display_name: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_default(self) -> bool:
        """Check if this is the default/single-tenant context."""
        return self.tenant_id == DEFAULT_TENANT


# ─── Tenant registry ────────────────────────────────────────────────────────


class TenantRegistry:
    """Registry of known tenants and their configurations.

    In production, tenants are configured via environment or config file.
    The registry supports:
      - Registering tenants with metadata
      - Looking up tenants by ID
      - Mapping API tokens to tenants
      - Listing all tenants
    """

    def __init__(self) -> None:
        self._tenants: dict[str, TenantContext] = {}
        self._token_map: dict[str, TenantId] = {}  # token_hash -> tenant
        self._lock = threading.Lock()

    def register(self, context: TenantContext) -> None:
        """Register a tenant context."""
        with self._lock:
            self._tenants[context.tenant_id.normalized] = context
            logger.info("Registered tenant: %s", context.tenant_id)

    def unregister(self, tenant_id: TenantId) -> None:
        """Remove a tenant from the registry."""
        with self._lock:
            self._tenants.pop(tenant_id.normalized, None)
            # Remove token mappings for this tenant
            self._token_map = {k: v for k, v in self._token_map.items() if v != tenant_id}

    def get(self, tenant_id: TenantId) -> TenantContext | None:
        """Look up a tenant by ID. Returns None if not found."""
        with self._lock:
            return self._tenants.get(tenant_id.normalized)

    def list_tenants(self) -> list[TenantContext]:
        """List all registered tenants."""
        with self._lock:
            return list(self._tenants.values())

    def map_token(self, token_hash: str, tenant_id: TenantId) -> None:
        """Map an API token hash to a tenant.

        When a request authenticates with this token, it is
        automatically associated with the mapped tenant.
        """
        with self._lock:
            self._token_map[token_hash] = tenant_id

    def resolve_tenant(self, token_hash: str, header_tenant: str | None = None) -> TenantId:
        """Resolve the tenant for a request.

        Resolution order:
          1. X-Tenant header (explicit override)
          2. Token-to-tenant mapping
          3. DEFAULT_TENANT (single-tenant fallback)

        Args:
            token_hash: SHA-256 hash of the API token.
            header_tenant: Value of X-Tenant HTTP header (if present).

        Returns:
            The resolved TenantId.
        """
        # 1. Explicit header override
        if header_tenant:
            try:
                tid = TenantId(header_tenant)
                # Verify tenant exists in registry
                with self._lock:
                    if tid.normalized in self._tenants:
                        return tid
                logger.warning("X-Tenant header '%s' not found in registry, falling back", header_tenant)
            except ValueError:
                logger.warning("Invalid X-Tenant header: '%s'", header_tenant)

        # 2. Token mapping
        with self._lock:
            mapped = self._token_map.get(token_hash)
            if mapped is not None:
                return mapped

        # 3. Default
        return DEFAULT_TENANT

    @property
    def tenant_count(self) -> int:
        """Number of registered tenants."""
        with self._lock:
            return len(self._tenants)


# ─── Module-level singleton ─────────────────────────────────────────────────


_registry_lock = threading.Lock()
_registry: TenantRegistry | None = None


def get_tenant_registry() -> TenantRegistry:
    """Get the global tenant registry (lazy init)."""
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = TenantRegistry()
    return _registry


def setup_tenant_registry(tenants: list[TenantContext] | None = None) -> TenantRegistry:
    """Configure and return the global tenant registry."""
    global _registry
    _registry = TenantRegistry()
    if tenants:
        for ctx in tenants:
            _registry.register(ctx)
    return _registry


def reset_tenant_registry() -> None:
    """Reset the global tenant registry (for testing)."""
    global _registry
    _registry = None


# ─── Environment-based configuration ────────────────────────────────────────


def load_tenants_from_env() -> TenantRegistry:
    """Load tenant configuration from environment variables.

    Format:
      PICODOME_TENANTS=team1:Team One;team2:Team Two
      PICODOME_TENANT_TOKEN_MAP=<token_hash>:<tenant_id>,...

    The token hash is the SHA-256 hash of the API token.
    """
    registry = setup_tenant_registry()

    # Load tenants
    tenants_str = os.environ.get("PICODOME_TENANTS", "")
    if tenants_str:
        for entry in tenants_str.split(";"):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split(":", 1)
            tid = TenantId(parts[0])
            display_name = parts[1] if len(parts) > 1 else parts[0]
            registry.register(
                TenantContext(
                    tenant_id=tid,
                    display_name=display_name,
                )
            )

    # Load token-to-tenant mappings
    token_map_str = os.environ.get("PICODOME_TENANT_TOKEN_MAP", "")
    if token_map_str:
        for entry in token_map_str.split(","):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split(":", 1)
            if len(parts) == 2:
                token_hash, tenant_id_str = parts
                try:
                    tid = TenantId(tenant_id_str)
                    registry.map_token(token_hash.strip(), tid)
                except ValueError:
                    logger.warning("Invalid tenant ID in token mapping: %s", tenant_id_str)

    return registry


# ─── Tenant-aware storage key ──────────────────────────────────────────────


def tenant_key(tenant_id: TenantId, key: str) -> str:
    """Create a tenant-namespaced storage key.

    Format: tenant:<tenant_id>:<key>

    This ensures different tenants' data doesn't collide
    in shared storage (Redis, file system, etc.).
    """
    return f"tenant:{tenant_id.normalized}:{key}"
