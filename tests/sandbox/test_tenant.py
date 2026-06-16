"""Tests for multi-tenant isolation — B08.

Covers:
- TenantId creation, validation, normalization
- TenantContext (display name, metadata, is_default)
- TenantRegistry (register, unregister, get, list)
- Token-to-tenant mapping
- resolve_tenant (header → token map → default)
- Environment loading
- tenant_key namespacing
- DEFAULT_TENANT sentinel
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

from picosentry.sandbox.tenant import (
    DEFAULT_TENANT,
    TenantContext,
    TenantId,
    TenantRegistry,
    get_tenant_registry,
    load_tenants_from_env,
    reset_tenant_registry,
    setup_tenant_registry,
    tenant_key,
)


class TestTenantId:
    def test_create_valid(self):
        tid = TenantId("team-platform")
        assert tid.normalized == "team-platform"
        assert str(tid) == "team-platform"

    def test_normalize_lowercase(self):
        tid = TenantId("Team-Platform")
        assert tid.normalized == "team-platform"

    def test_normalize_strip_whitespace(self):
        tid = TenantId("  team-platform  ")
        assert tid.normalized == "team-platform"

    def test_underscores_allowed(self):
        tid = TenantId("team_platform")
        assert tid.normalized == "team_platform"

    def test_hyphens_allowed(self):
        tid = TenantId("team-platform")
        assert tid.normalized == "team-platform"

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            TenantId("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            TenantId("   ")

    def test_invalid_chars_raises(self):
        with pytest.raises(ValueError, match="invalid characters"):
            TenantId("team@platform")

    def test_spaces_in_value_raises(self):
        with pytest.raises(ValueError, match="invalid characters"):
            TenantId("team platform")

    def test_equality(self):
        a = TenantId("Team-Alpha")
        b = TenantId("team-alpha")
        assert a == b

    def test_equality_with_string(self):
        tid = TenantId("team-alpha")
        assert tid == "team-alpha"
        assert tid == "Team-Alpha"

    def test_inequality(self):
        a = TenantId("team-alpha")
        b = TenantId("team-beta")
        assert a != b

    def test_hashable(self):
        tid = TenantId("team-alpha")
        d = {tid: "value"}
        assert d[TenantId("Team-Alpha")] == "value"

    def test_frozen(self):
        tid = TenantId("team-alpha")
        with pytest.raises(AttributeError):
            tid.value = "changed"


class TestTenantContext:
    def test_basic_context(self):
        ctx = TenantContext(tenant_id=TenantId("team-alpha"))
        assert ctx.tenant_id == TenantId("team-alpha")
        assert ctx.display_name == ""
        assert ctx.metadata == {}

    def test_with_display_name(self):
        ctx = TenantContext(
            tenant_id=TenantId("alpha"),
            display_name="Team Alpha",
        )
        assert ctx.display_name == "Team Alpha"

    def test_with_metadata(self):
        ctx = TenantContext(
            tenant_id=TenantId("alpha"),
            metadata={"quota": 100, "region": "us-east"},
        )
        assert ctx.metadata["quota"] == 100

    def test_is_default(self):
        assert TenantContext(tenant_id=DEFAULT_TENANT).is_default
        assert not TenantContext(tenant_id=TenantId("alpha")).is_default

    def test_frozen(self):
        ctx = TenantContext(tenant_id=TenantId("alpha"))
        with pytest.raises(AttributeError):
            ctx.display_name = "changed"


class TestDefaultTenant:
    def test_default_tenant_value(self):
        assert DEFAULT_TENANT.normalized == "default"

    def test_default_tenant_equality(self):
        assert TenantId("default") == DEFAULT_TENANT
        assert TenantId("Default") == DEFAULT_TENANT


class TestTenantRegistry:
    def setup_method(self):
        self.registry = TenantRegistry()

    def test_register_and_get(self):
        ctx = TenantContext(tenant_id=TenantId("alpha"), display_name="Team Alpha")
        self.registry.register(ctx)
        result = self.registry.get(TenantId("alpha"))
        assert result is not None
        assert result.display_name == "Team Alpha"

    def test_get_not_found(self):
        assert self.registry.get(TenantId("nonexistent")) is None

    def test_unregister(self):
        ctx = TenantContext(tenant_id=TenantId("alpha"))
        self.registry.register(ctx)
        self.registry.unregister(TenantId("alpha"))
        assert self.registry.get(TenantId("alpha")) is None

    def test_list_tenants(self):
        self.registry.register(TenantContext(tenant_id=TenantId("alpha")))
        self.registry.register(TenantContext(tenant_id=TenantId("beta")))
        tenants = self.registry.list_tenants()
        assert len(tenants) == 2

    def test_tenant_count(self):
        assert self.registry.tenant_count == 0
        self.registry.register(TenantContext(tenant_id=TenantId("alpha")))
        assert self.registry.tenant_count == 1

    def test_register_overwrites(self):
        self.registry.register(TenantContext(tenant_id=TenantId("alpha"), display_name="V1"))
        self.registry.register(TenantContext(tenant_id=TenantId("alpha"), display_name="V2"))
        ctx = self.registry.get(TenantId("alpha"))
        assert ctx is not None
        assert ctx.display_name == "V2"

    def test_case_insensitive_lookup(self):
        self.registry.register(TenantContext(tenant_id=TenantId("Alpha")))
        ctx = self.registry.get(TenantId("alpha"))
        assert ctx is not None

    def test_map_token(self):
        self.registry.register(TenantContext(tenant_id=TenantId("alpha")))
        self.registry.map_token("abc123hash", TenantId("alpha"))
        resolved = self.registry.resolve_tenant("abc123hash")
        assert resolved == TenantId("alpha")

    def test_resolve_tenant_header_override(self):
        self.registry.register(TenantContext(tenant_id=TenantId("alpha")))
        self.registry.map_token("abc123hash", TenantId("beta"))
        # Header takes precedence over token mapping
        resolved = self.registry.resolve_tenant("abc123hash", header_tenant="alpha")
        assert resolved == TenantId("alpha")

    def test_resolve_tenant_token_mapping(self):
        self.registry.register(TenantContext(tenant_id=TenantId("alpha")))
        self.registry.map_token("abc123hash", TenantId("alpha"))
        resolved = self.registry.resolve_tenant("abc123hash")
        assert resolved == TenantId("alpha")

    def test_resolve_tenant_default_fallback(self):
        resolved = self.registry.resolve_tenant("unknown-token")
        assert resolved == DEFAULT_TENANT

    def test_resolve_tenant_invalid_header(self):
        # Invalid header falls back to token mapping
        self.registry.register(TenantContext(tenant_id=TenantId("alpha")))
        self.registry.map_token("abc123hash", TenantId("alpha"))
        resolved = self.registry.resolve_tenant("abc123hash", header_tenant="invalid@id")
        assert resolved == TenantId("alpha")

    def test_resolve_tenant_header_not_registered(self):
        # Header with unregistered tenant falls back
        self.registry.register(TenantContext(tenant_id=TenantId("alpha")))
        resolved = self.registry.resolve_tenant("unknown", header_tenant="nonexistent")
        assert resolved == DEFAULT_TENANT

    def test_unregister_removes_token_mapping(self):
        self.registry.register(TenantContext(tenant_id=TenantId("alpha")))
        self.registry.map_token("abc123hash", TenantId("alpha"))
        self.registry.unregister(TenantId("alpha"))
        resolved = self.registry.resolve_tenant("abc123hash")
        assert resolved == DEFAULT_TENANT


class TestTenantKey:
    def test_basic_key(self):
        key = tenant_key(TenantId("alpha"), "scan:123")
        assert key == "tenant:alpha:scan:123"

    def test_normalizes_tenant_id(self):
        key = tenant_key(TenantId("Team-Alpha"), "job:456")
        assert key == "tenant:team-alpha:job:456"

    def test_default_tenant_key(self):
        key = tenant_key(DEFAULT_TENANT, "config")
        assert key == "tenant:default:config"

    def test_different_tenants_different_keys(self):
        k1 = tenant_key(TenantId("alpha"), "scan:1")
        k2 = tenant_key(TenantId("beta"), "scan:1")
        assert k1 != k2


class TestModuleSingleton:
    def setup_method(self):
        reset_tenant_registry()

    def teardown_method(self):
        reset_tenant_registry()

    def test_get_registry_creates_default(self):
        registry = get_tenant_registry()
        assert isinstance(registry, TenantRegistry)

    def test_setup_registry(self):
        ctx = TenantContext(tenant_id=TenantId("alpha"))
        registry = setup_tenant_registry([ctx])
        assert registry.tenant_count == 1

    def test_reset_clears_registry(self):
        setup_tenant_registry([TenantContext(tenant_id=TenantId("alpha"))])
        reset_tenant_registry()
        # New registry should be empty
        registry = get_tenant_registry()
        assert registry.tenant_count == 0


class TestEnvLoading:
    def setup_method(self):
        reset_tenant_registry()

    def teardown_method(self):
        reset_tenant_registry()

    def test_load_tenants_from_env(self):
        with mock.patch.dict(
            os.environ,
            {
                "PICODOME_TENANTS": "alpha:Team Alpha;beta:Team Beta",
            },
            clear=False,
        ):
            registry = load_tenants_from_env()
            assert registry.tenant_count == 2
            ctx = registry.get(TenantId("alpha"))
            assert ctx is not None
            assert ctx.display_name == "Team Alpha"

    def test_load_token_map_from_env(self):
        with mock.patch.dict(
            os.environ,
            {
                "PICODOME_TENANTS": "alpha:Team Alpha",
                "PICODOME_TENANT_TOKEN_MAP": "hash1:alpha,hash2:alpha",
            },
            clear=False,
        ):
            registry = load_tenants_from_env()
            resolved = registry.resolve_tenant("hash1")
            assert resolved == TenantId("alpha")

    def test_empty_env(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            registry = load_tenants_from_env()
            assert registry.tenant_count == 0

    def test_tenant_without_display_name(self):
        with mock.patch.dict(
            os.environ,
            {
                "PICODOME_TENANTS": "alpha",
            },
            clear=False,
        ):
            registry = load_tenants_from_env()
            ctx = registry.get(TenantId("alpha"))
            assert ctx is not None
            assert ctx.display_name == "alpha"
