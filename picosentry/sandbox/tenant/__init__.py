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


class TenantMismatchError(PermissionError):
    """X-Tenant header names a tenant other than the token's mapped tenant."""

    def __init__(self, requested: TenantId, effective: TenantId) -> None:
        self.requested = requested
        self.effective = effective
        super().__init__(f"X-Tenant header '{requested}' does not match token-mapped tenant '{effective}'")


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
        self._operator_tokens: set[str] = set()  # token_hashes allowed to cross tenants
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

    def map_operator_token(self, token_hash: str) -> None:
        """Designate a token (by hash) as operator: it may select any
        registered tenant via X-Tenant and sees all tenants in listings."""
        with self._lock:
            self._operator_tokens.add(token_hash)

    def is_operator_token(self, token_hash: str) -> bool:
        with self._lock:
            return token_hash in self._operator_tokens

    def resolve_tenant(self, token_hash: str, header_tenant: str | None = None) -> TenantId:
        """Resolve the effective tenant for a request (WO5.0.0-001).

        The token's mapped tenant always wins. The X-Tenant header may only
        *confirm* that tenant; naming any other tenant raises
        TenantMismatchError (treated as unauthorized by the callers).
        Explicitly-designated operator tokens are the exception: they may
        select any registered tenant via the header.
        """
        with self._lock:
            mapped = self._token_map.get(token_hash)
            is_operator = token_hash in self._operator_tokens

        header_tid: TenantId | None = None
        if header_tenant:
            try:
                header_tid = TenantId(header_tenant)
            except ValueError:
                logger.warning("Invalid X-Tenant header: %r", header_tenant)

        if is_operator:
            if header_tid is not None and self.get(header_tid) is not None:
                return header_tid
            return mapped or DEFAULT_TENANT

        effective = mapped or DEFAULT_TENANT
        if header_tid is not None and header_tid != effective:
            logger.warning(
                "X-Tenant header '%s' does not match token-mapped tenant '%s' — rejecting",
                header_tid.normalized,
                effective.normalized,
            )
            raise TenantMismatchError(header_tid, effective)
        return effective

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
    """Build the process tenant registry from the environment.

    Env vars (read by PicoDomeDaemon.__init__ and the gRPC server):

    - ``PICODOME_TENANTS``: ``id:Display Name;id2:Name2`` — tenants to register.
    - ``PICODOME_TENANT_TOKEN_MAP``: ``<sha256(token)>:tenant_id,...`` — maps an
      API token (by hex sha256 of its raw value) to its tenant.
    - ``PICODOME_TENANT_OPERATOR_TOKENS``: ``<sha256(token)},...`` — tokens that
      may set X-Tenant to any registered tenant and see all tenants in
      listings (operator/cluster use).
    """
    registry = setup_tenant_registry()

    tenants_str = os.environ.get("PICODOME_TENANTS", "")
    if tenants_str:
        for raw_entry in tenants_str.split(";"):
            entry = raw_entry.strip()
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
        for raw_entry in token_map_str.split(","):
            entry = raw_entry.strip()
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

    operators_str = os.environ.get("PICODOME_TENANT_OPERATOR_TOKENS", "")
    if operators_str:
        for raw_entry in operators_str.split(","):
            token_hash = raw_entry.strip()
            if token_hash:
                registry.map_operator_token(token_hash)

    return registry


def tenant_key(tenant_id: TenantId, key: str) -> str:
    return f"tenant:{tenant_id.normalized}:{key}"
