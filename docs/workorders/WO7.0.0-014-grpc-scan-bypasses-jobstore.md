# WO7.0.0-014 — Sandbox: gRPC Scan RPC bypasses job_store — scans not persisted, not tenant-scoped in store

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/grpc-scan-jobstore`)
**Priority:** P1 · Effort M · Risk M
**Scope:** `picosentry/sandbox/grpc_transport/_servicer.py`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + test: a gRPC Scan call creates a job_store row retrievable via the HTTP API (tenant-scoped); the row's `tenant_id` matches the caller.

## Objective
`servicer.Scan` calls `engine.scan()` directly and never touches the job_store. gRPC scans are not persisted and not retrievable via the HTTP API — two transports, two storage fates.

## Evidence (verified 2026-08-20, explorer SA-sandbox; file:line chain)
- `_servicer.py:75-137`: `Scan` builds a request, calls `engine.scan()`, returns the result — no `job_store.add`/`update`.
- HTTP path goes through `TenantAwareScanJobStore`; gRPC path does not.

## Deliverables
1. Persist gRPC scans via `TenantAwareScanJobStore` (add → run → update), tenant-scoped to the caller.
2. Regression test per the gate.