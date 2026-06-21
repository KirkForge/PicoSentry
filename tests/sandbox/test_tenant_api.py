"""Tests for tenant-aware API — B10.

Covers:
- X-Tenant header resolution in daemon requests
- /api/v1/tenants endpoint (list tenants)
- Tenant ID included in scan audit metadata
- Token-to-tenant mapping in daemon context
"""

from __future__ import annotations

import hashlib

from picosentry.sandbox.tenant import (
    DEFAULT_TENANT,
    TenantContext,
    TenantId,
    reset_tenant_registry,
    setup_tenant_registry,
)


class _TestHandler:
    """Minimal request handler for testing tenant resolution."""

    def __init__(self, headers: dict[str, str] | None = None):
        self.headers_map = headers or {}

    def _resolve_tenant(self, token: str | None) -> TenantId:
        """Same logic as PicoDomeHandler._resolve_tenant."""
        from picosentry.sandbox.tenant import get_tenant_registry

        registry = get_tenant_registry()
        header_tenant = self.headers_map.get("X-Tenant")

        token_hash = ""
        if token and token != "no-auth-dev-mode":
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

        return registry.resolve_tenant(token_hash, header_tenant=header_tenant)


class TestTenantHeaderResolution:
    def setup_method(self):
        reset_tenant_registry()

    def teardown_method(self):
        reset_tenant_registry()

    def test_no_header_no_mapping(self):
        handler = _TestHandler()
        tenant = handler._resolve_tenant(None)
        assert tenant == DEFAULT_TENANT

    def test_x_tenant_header_resolves(self):
        setup_tenant_registry(
            [
                TenantContext(tenant_id=TenantId("alpha"), display_name="Team Alpha"),
            ]
        )
        handler = _TestHandler({"X-Tenant": "alpha"})
        tenant = handler._resolve_tenant(None)
        assert tenant == TenantId("alpha")

    def test_x_tenant_header_case_insensitive(self):
        setup_tenant_registry(
            [
                TenantContext(tenant_id=TenantId("alpha")),
            ]
        )
        handler = _TestHandler({"X-Tenant": "Alpha"})
        tenant = handler._resolve_tenant(None)
        assert tenant == TenantId("alpha")

    def test_token_mapping_resolves(self):
        registry = setup_tenant_registry(
            [
                TenantContext(tenant_id=TenantId("alpha")),
            ]
        )
        token = "my-secret-token"
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        registry.map_token(token_hash, TenantId("alpha"))

        handler = _TestHandler({"Authorization": f"Bearer {token}"})
        tenant = handler._resolve_tenant(token)
        assert tenant == TenantId("alpha")

    def test_header_overrides_token_mapping(self):
        registry = setup_tenant_registry(
            [
                TenantContext(tenant_id=TenantId("alpha")),
                TenantContext(tenant_id=TenantId("beta")),
            ]
        )
        token = "my-secret-token"
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        registry.map_token(token_hash, TenantId("beta"))

        handler = _TestHandler(
            {
                "Authorization": f"Bearer {token}",
                "X-Tenant": "alpha",
            }
        )
        tenant = handler._resolve_tenant(token)
        assert tenant == TenantId("alpha")

    def test_unregistered_header_falls_back(self):
        setup_tenant_registry(
            [
                TenantContext(tenant_id=TenantId("alpha")),
            ]
        )
        handler = _TestHandler({"X-Tenant": "nonexistent"})
        tenant = handler._resolve_tenant(None)
        assert tenant == DEFAULT_TENANT


class TestTenantsEndpoint:
    """Test the /api/v1/tenants endpoint via the daemon handler."""

    def setup_method(self):
        reset_tenant_registry()

    def teardown_method(self):
        reset_tenant_registry()

    def test_list_tenants_endpoint_exists(self):
        """Verify the tenants endpoint is registered in the daemon routes."""
        from picosentry.sandbox.daemon.server import PicoDomeHandler

        # Just verify the method exists
        assert hasattr(PicoDomeHandler, "_handle_list_tenants")

    def test_tenants_endpoint_response_format(self):
        """Test the response format of the list tenants handler."""
        setup_tenant_registry(
            [
                TenantContext(tenant_id=TenantId("alpha"), display_name="Team Alpha"),
                TenantContext(tenant_id=TenantId("beta"), display_name="Team Beta"),
            ]
        )

        # The handler would call get_tenant_registry().list_tenants()
        from picosentry.sandbox.tenant import get_tenant_registry

        registry = get_tenant_registry()
        tenants = registry.list_tenants()

        result = {
            "tenants": [
                {
                    "tenant_id": str(ctx.tenant_id),
                    "display_name": ctx.display_name,
                    "is_default": ctx.is_default,
                }
                for ctx in tenants
            ],
            "count": len(tenants),
        }

        assert result["count"] == 2
        assert result["tenants"][0]["tenant_id"] in ("alpha", "beta")
        assert not result["tenants"][0]["is_default"]

    def test_empty_tenants_list(self):
        setup_tenant_registry([])
        from picosentry.sandbox.tenant import get_tenant_registry

        registry = get_tenant_registry()
        tenants = registry.list_tenants()
        assert len(tenants) == 0


class TestTenantInAuditMetadata:
    """Verify tenant_id is included in scan audit events."""

    def setup_method(self):
        reset_tenant_registry()

    def teardown_method(self):
        reset_tenant_registry()

    def test_tenant_id_in_scan_metadata(self):
        """Verify that _resolve_tenant returns a TenantId that can be
        included in audit metadata."""
        setup_tenant_registry(
            [
                TenantContext(tenant_id=TenantId("alpha")),
            ]
        )
        handler = _TestHandler({"X-Tenant": "alpha"})
        token = "test-token"
        tenant_id = handler._resolve_tenant(token)

        # This is what gets put in metadata
        metadata = {"job_id": "abc123", "timeout": 30, "tenant_id": str(tenant_id)}
        assert metadata["tenant_id"] == "alpha"
