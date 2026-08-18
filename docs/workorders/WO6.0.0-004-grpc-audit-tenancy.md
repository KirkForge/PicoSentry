# WO6.0.0-004 — Sandbox: gRPC QueryAudit leaks all tenants' audit events to tenant-scoped tokens

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/grpc-audit-tenancy`)
**Priority:** P0 · Effort S · Risk L
**Scope:** `picosentry/sandbox/grpc_transport/_servicer.py`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + gRPC/HTTP tenant-scope parity test (matrix over read surfaces × transports): tenant token sees only its tenant's audit events on BOTH transports; operator sees all.

## Objective
WO5-001's tenancy exists on the HTTP audit route only — the gRPC mirror never filters.

## Evidence (verified 2026-08-18, explorer SA-AQ; live repro repro_grpc_audit_tenant.py)
`_servicer.py:242-294` QueryAudit returns events for ALL tenants; the interceptor enforces RBAC (`audit:read`, which READER holds) but the servicer applies no tenant filter — `_resolve_tenant` exists and is used for Scan (`:70`) but not QueryAudit. Live: beta-tenant reader token via gRPC → `['server listening…', 'beta job', 'alpha job']` (HTTP equivalent correctly returns `['beta job']`). Audit events carry command lines, job IDs, tenant IDs, actor hashes. `test_grpc_auth.py` has zero multi-tenant audit coverage.

## Deliverables
1. QueryAudit resolves tenant via the same `_resolve_tenant(context)` path and filters `metadata.tenant_id` for non-operator tokens (mirror the HTTP route at `handler_routes_get.py:337-344`).
2. The parity matrix test from the gate (covers this WO + regression-guards the HTTP side).
