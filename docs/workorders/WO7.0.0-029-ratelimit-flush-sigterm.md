# WO7.0.0-029 — Serve: rate-limit background flush thread not stopped in SIGTERM (spurious post-`db.close` errors)

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/ratelimit-flush-sigterm`)
**Priority:** P2 · Effort S · Risk L
**Scope:** `picosentry/serve/api/server.py`, `picosentry/serve/middleware/rate_limit.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + test: SIGTERM stops the rate-limit flush thread before `db.close()`; no post-shutdown flush errors in the log.

## Objective
Shutdown stops the outbox poller but not the rate-limit flush thread. The thread keeps writing after `db.close()` → spurious errors in the shutdown log.

## Evidence (verified 2026-08-20, explorer SA-seam; file:line chain)
- `server.py:437-450`: lifespan shutdown stops the outbox poller; no `rate_limiter.shutdown()` call.
- `rate_limit.py:115-130`: background flush thread runs until the process exits.

## Deliverables
1. Call `rate_limiter.shutdown()` in lifespan shutdown + SIGTERM path (before `db.close()`).
2. Regression test per the gate.