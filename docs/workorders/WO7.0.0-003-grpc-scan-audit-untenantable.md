# WO7.0.0-003 — Sandbox: gRPC Scan RPC audit events not attributable and not tenant-tagged

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/grpc-scan-audit-tenant`)
**Priority:** P0 · Effort S · Risk M
**Scope:** `picosentry/sandbox/grpc_transport/_servicer.py`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + test: a gRPC Scan call by tenant A produces an audit row whose `metadata["tenant_id"] == A` and is reachable by tenant A's audit query, invisible to tenant B.

## Objective
`_audit_log` for gRPC Scan uses hardcoded `actor="picodome-grpc"`, passes NO `metadata` and NO `target`. Tenant-scoped audit queries filter on `metadata.get("tenant_id")` → gRPC scan events are invisible to every tenant and cannot be attributed.

## Evidence (verified 2026-08-20, explorer SA-sandbox; file:line chain)
- `_servicer.py:361-377`: `_audit_log(...)` call uses literal `actor="picodome-grpc"`; no token-derived actor, no tenant_id, no metadata dict, no target.
- Tenant filter on audit queries checks `metadata.get("tenant_id")` — gRPC scan events lack the key.
- gRPC auth interceptor (`auth.py:106-136`) has the caller's token in scope but the servicer never threads it through.

## Deliverables
1. `_audit_log` accepts the caller's token, computes an actor hash (mirroring HTTP path), and passes `tenant_id` + `metadata` + `target`.
2. Regression test per the gate (tenant A sees its own gRPC scan audit; tenant B does not).