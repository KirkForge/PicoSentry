# WO7.0.0-015 — Sandbox: gRPC auth interceptor skips rate limiting — DoS with a valid token

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/grpc-ratelimit`)
**Priority:** P1 · Effort S · Risk M
**Scope:** `picosentry/sandbox/grpc_transport/auth.py`, `picosentry/sandbox/daemon/handler_mixins.py`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + test: a single token issuing >N gRPC calls within the window is throttled (RESOURCE_EXHAUSTED / 429), matching the HTTP path.

## Objective
The gRPC interceptor validates the token + RBAC but never calls `rate_limiter.allow(actor)`. One valid token can monopolize all 10 `ThreadPoolExecutor` slots — DoS with valid creds.

## Evidence (verified 2026-08-20, explorer SA-sandbox; file:line chain)
- `auth.py:106-136`: interceptor does token validation + RBAC only; no rate-limiter call.
- `handler_mixins.py:202-214`: HTTP path calls `rate_limiter.allow(actor)` and rejects on over-budget.
- gRPC has 10 worker slots, all reachable by one token.

## Deliverables
1. gRPC interceptor calls `rate_limiter.allow(actor)` and returns `RESOURCE_EXHAUSTED` on denial (mirror HTTP semantics).
2. Regression test per the gate.