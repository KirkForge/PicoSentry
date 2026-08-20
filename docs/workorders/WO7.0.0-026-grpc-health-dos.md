# WO7.0.0-026 — Sandbox: gRPC `Health()` unauthenticated + calls expensive `check_health()` (DoS)

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/grpc-health-dos`)
**Priority:** P1 · Effort S · Risk M
**Scope:** `picosentry/sandbox/grpc_transport/_servicer.py`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + test: unauthenticated `Health()` is rate-limited or cheap (no audit-chain walk per call); p99 latency <50ms under 100 concurrent calls.

## Objective
`Health()` is not in `METHOD_PERMISSIONS` → no auth; it calls `check_health()` which walks the audit chain. An unauthenticated client can DoS by hammering `Health()`.

## Evidence (verified 2026-08-20, explorer SA-sandbox; file:line chain)
- `_servicer.py:172-201`: `Health` handler calls `check_health()` (full audit-chain traversal) on every call.
- `auth.py` METHOD_PERMISSIONS omits `Health` → interceptor skips auth + RBAC.

## Deliverables
1. Cache `check_health()` with a short TTL (e.g. 5s) OR make `Health()` cheap (cheap liveness vs. expensive readiness); add `Health` to `METHOD_PERMISSIONS` as a public-read.
2. Regression test per the gate (concurrent unauthenticated calls don't starve workers).