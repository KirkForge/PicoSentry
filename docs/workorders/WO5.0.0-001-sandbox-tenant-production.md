# WO5.0.0-001 — Sandbox: tenant isolation is dead in production

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/sandbox-tenant`)
**Priority:** P0 · Effort M · Risk M
**Scope:** `picosentry/sandbox/tenant/**`, `picosentry/sandbox/daemon/{daemon.py,handler_mixins.py,handler_routes_get.py}`, `picosentry/sandbox/grpc_transport/_servicer.py`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + new tests: daemon booted via `PICODOME_TENANTS` + `PICODOME_TENANT_TOKEN_MAP` (not hand-wired handler) → two tokens land in different tenants; foreign token + victim `X-Tenant` header → denied; sqlite pre-tenancy row (NULL tenant_id) readable as DEFAULT tenant.

## Objective
Multi-tenancy must actually exist outside tests: the env loader must be wired into daemon/gRPC startup, the `X-Tenant` header must not override token→tenant mapping, and pre-upgrade jobs must stay visible.

## Evidence (verified 2026-08-18, explorer SA-S; live repros in report)
1. **`load_tenants_from_env()` has zero production callers** (CRITICAL): defined at `tenant/__init__.py:141`, referenced only by `tests/sandbox/test_tenant.py`. `PicoDomeDaemon.__init__` never builds a registry; `handler_mixins.py:128-141` lazily gets an EMPTY registry. Live: daemon started with `PICODOME_TENANTS=acme:Acme,globex:Globex` + token map → every request resolves DEFAULT tenant; log "X-Tenant header 'acme' not found in registry, falling back". WO4.0.0-010 wired the store wrapper, but all tenants share one job namespace in production.
2. **X-Tenant header overrides token mapping with no cross-check** (HIGH): `tenant/__init__.py:88-106` checks `header_tenant` FIRST and returns it if registered. Live: globex token + `X-Tenant: acme` → read an acme-owned job (200) and submitted a job into acme's namespace. Mirror in `grpc_transport/_servicer.py:286-300`.
3. **Audit surface not tenant-scoped**: `handler_routes_get.py:131-134` — `audit:read` returns all tenants' events (incl. full commands in `detail`); `/api/v1/tenants` global. Matters the moment (1) is fixed.
4. **sqlite NULL tenant_id ≠ jsonl missing key**: `tenant/store.py:47` — `job.get("tenant_id", DEFAULT)` never applies the default for sqlite rows (key present, value None) → pre-upgrade jobs invisible to everyone. jsonl rows behave correctly.

## Deliverables
1. Call `load_tenants_from_env()` in `PicoDomeDaemon.__init__` and gRPC server start; document both env vars.
2. `resolve_tenant`: header may only *narrow* within the token's mapped tenant; reject mismatch (allow-listed operator/cluster tokens excepted).
3. Tenant-scope audit queries and `/api/v1/tenants` (decision: operator tokens see all, tenants see own).
4. Normalize NULL `tenant_id` to DEFAULT at the store boundary.
5. End-to-end daemon-level tenant tests (boot the daemon, not a hand-wired handler).
