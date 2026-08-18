# WO5.0.0-017 — Sandbox: job-store correctness (prune, orphans, redis honesty)

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/sandbox-store`)
**Priority:** P1 · Effort M · Risk L
**Scope:** `picosentry/sandbox/daemon/{sqlite_store.py,redis_store.py,daemon.py,handler_routes_post.py}`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + new tests: `prune(max_jobs > count)` deletes nothing; failed-validation submit leaves no pending row; `PICODOME_STORE_BACKEND=redis` with Redis down is loud (rejected startup or logged errors, never a fake 201).

## Objective
The job store must not delete everything on a well-meant prune, accumulate zombie jobs, or pretend to accept work it can't persist.

## Evidence (verified 2026-08-18, explorer SA-S; live repros)
1. **`prune(max_jobs=N > count)` deletes EVERY job**: `sqlite_store.py:221-237` — `LIMIT (SELECT COUNT(*)) - ?` goes negative; negative LIMIT = unlimited in SQLite. Live: 3 jobs, `prune(max_jobs=10)` → all 3 deleted. Public API footgun; internal `_prune_old_jobs` only calls over-cap.
2. **Orphaned `pending` jobs**: submit persists the job before policy/backend validation, then error-returns without failing it (`handler_routes_post.py:172` add vs `:192-197,214-215` error returns). Live: nonexistent policy → 400, store retains a `pending` job forever; `GET /scans` shows jobs that never ran.
3. **Redis store honesty**: comment promises hash TTL but no `EXPIRE` exists anywhere (`redis_store.py:131-134`) → unbounded `picodome:job:*` growth; unavailable `add` returns a success-shaped pending dict and `get` → None (`:101-114`) → 201-accepted job later 404s; `PICODOME_STORE_BACKEND=redis` silently falls back to jsonl (`daemon.py:60-75`) — misconfiguration unvalidated, backend unwired.

## Deliverables
1. `max(0, count - limit)` guard in prune SQL (or Python-side).
2. Mark job failed on every early-return, or validate before `add`.
3. Redis: real TTL, loud unavailability (raise/log, no fake success), wire the backend selector or delete it + validate the env var.
