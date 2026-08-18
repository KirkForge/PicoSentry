# WO5.0.0-020 — Serve: event-loop hygiene remainder (ready/history/projects/redis)

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/serve-loop`)
**Priority:** P1 · Effort M · Risk L
**Scope:** `picosentry/serve/api/routers/{health.py,projects.py}`, `picosentry/serve/middleware/rate_limit.py`, `picosentry/serve/api/server.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + test (or grep-pin) that no `db.execute*`/sync-redis call remains directly inside `async def` handlers on these routes.

## Objective
Close the WO-013 remainder: the same sync-on-loop class it fixed, on the routes it missed.

## Evidence (verified 2026-08-18, explorer SA-T; code chains)
1. **`/health/ready`** (`routers/health.py:87-112`): `db.execute_one("SELECT 1")` inline in `async def`; rate-limit exempt (`server.py:329`), DDoS-shield exempt (`ddos_shield.py:22-27`), unauthenticated — on postgres each hit is a network roundtrip on the loop, hammerable for free.
2. **`/health/history`** (`health.py:115-129`) and all 13 projects-router read handlers (`routers/projects.py`): direct `db.execute` in `async def` (the run/batch endpoints correctly use `to_thread`).
3. **Redis rate-limit backend sync on the loop** (`rate_limit.py:211-221`): `record_and_count` (sync redis-py, 1s connect/socket timeouts, `rate_limit_redis.py:87-114`) called twice per request inside async `dispatch`. Worst case Redis configured-but-down: ~2s loop stall per request including unauthenticated paths — self-inflicted DoS amplifier. (The lock was moved off the Redis call previously; the loop call wasn't.)

## Deliverables
1. `to_thread` (or async client) for all four surfaces.
2. Consider whether the exempt-unauthenticated `/health/ready` should keep a cheap path (k8s contract) — document the choice.
