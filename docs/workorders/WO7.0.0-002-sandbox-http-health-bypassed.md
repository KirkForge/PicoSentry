# WO7.0.0-002 — Sandbox: HTTP /health hardcodes "healthy" — bypasses check_health()

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/http-health-bypassed`)
**Priority:** P0 · Effort S · Risk M
**Scope:** `picosentry/sandbox/daemon/handler_routes_get.py`, `picosentry/sandbox/health.py`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + test: with a broken dependency (e.g. job_store unreachable), HTTP `/health` returns non-200 matching the gRPC `Health()` verdict.

## Objective
The HTTP `_handle_health` returns `{"status": "healthy"}` unconditionally and never calls `check_health()` — the two transports disagree. HTTP health is a load-balancer gate, so a dead sandbox keeps receiving traffic.

## Evidence (verified 2026-08-20, explorer SA-sandbox; file:line chain)
- `handler_routes_get.py:172-194`: `_handle_health` sets `health_data = {"status": "healthy"}` and returns 200 regardless of subsystem state.
- `health.py:41-180`: `check_health()` walks job_store, audit chain, policy loader — gRPC `Health()` calls it; HTTP does not.
- `grpc_transport/_servicer.py:172-201`: gRPC path returns the real verdict.

## Deliverables
1. `_handle_health` calls `check_health()` and returns its verdict (status code + body) matching the gRPC semantics.
2. Regression test: inject a failing subsystem, assert HTTP `/health` reflects it.