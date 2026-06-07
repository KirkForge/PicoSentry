
from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("picodome.tenant")


@dataclass(frozen=True)
class TenantId:

    value: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("TenantId cannot be empty")

        normalized = self.value.strip().lower()

        if not all(c.isalnum() or c in "-_" for c in normalized):
            raise ValueError(
                f"TenantId '{self.value}' contains invalid characters. Use only alphanumeric, hyphens, and underscores."
            )

    @property
    def normalized(self) -> str:
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


DEFAULT_TENANT = TenantId("default")


@dataclass(frozen=True)
class TenantContext:

    tenant_id: TenantId
    display_name: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_default(self) -> bool:
        return self.tenant_id == DEFAULT_TENANT


class TenantRegistry:

    def __init__(self) -> None:
        self._tenants: dict[str, TenantContext] = {}
        self._token_map: dict[str, TenantId] = {}  # token_hash -> tenant
        self._lock = threading.Lock()

    def register(self, context: TenantContext) -> None:
        with self._lock:
            self._tenants[context.tenant_id.normalized] = context
            logger.info("Registered tenant: %s", context.tenant_id)

    def unregister(self, tenant_id: TenantId) -> None:
        with self._lock:
            self._tenants.pop(tenant_id.normalized, None)

            self._token_map = {k: v for k, v in self._token_map.items() if v != tenant_id}

    def get(self, tenant_id: TenantId) -> TenantContext | None:
        with self._lock:
            return self._tenants.get(tenant_id.normalized)

    def list_tenants(self) -> list[TenantContext]:
        with self._lock:
            return list(self._tenants.values())

    def map_token(self, token_hash: str, tenant_id: TenantId) -> None:
        with self._lock:
            self._token_map[token_hash] = tenant_id

    def resolve_tenant(self, token_hash: str, header_tenant: str | None = None) -> TenantId:

        if header_tenant:
            try:
                tid = TenantId(header_tenant)

                with self._lock:
                    if tid.normalized in self._tenants:
                        return tid
                logger.warning("X-Tenant header '%s' not found in registry, falling back", header_tenant)
            except ValueError:
                logger.warning("Invalid X-Tenant header: '%s'", header_tenant)


        with self._lock:
            mapped = self._token_map.get(token_hash)
            if mapped is not None:
                return mapped


        return DEFAULT_TENANT

    @property
    def tenant_count(self) -> int:
        with self._lock:
            return len(self._tenants)


_registry_lock = threading.Lock()
_registry: TenantRegistry | None = None


def get_tenant_registry() -> TenantRegistry:
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = TenantRegistry()
    return _registry


def setup_tenant_registry(tenants: list[TenantContext] | None = None) -> TenantRegistry:
    global _registry
    _registry = TenantRegistry()
    if tenants:
        for ctx in tenants:
            _registry.register(ctx)
    return _registry


def reset_tenant_registry() -> None:
    global _registry
    _registry = None


def load_tenants_from_env() -> TenantRegistry:
    registry = setup_tenant_registry()


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


def tenant_key(tenant_id: TenantId, key: str) -> str:
    return f"tenant:{tenant_id.normalized}:{key}"
