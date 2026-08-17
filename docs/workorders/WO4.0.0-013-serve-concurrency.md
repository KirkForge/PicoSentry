# WO4.0.0-013 — Serve: concurrency & event-loop hygiene

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/4.0.0/serve-concurrency`)
**Priority:** P1 · Effort M-L · Risk M
**Scope:** `picosentry/serve/api/deps.py`, `picosentry/serve/middleware/{audit.py,request_size_limit.py}`, `picosentry/serve/api/routers/health.py`, `picosentry/serve/services/_orchestrator_health.py`, `picosentry/serve/services/{backup.py,correlation/persistence.py}`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + a loop-blocking regression test (no handler-starvation > N ms under parallel /health + DB reads).

## Objective
Unblock the event loop, scope the global DB mutex, and make /health cheap.

## Evidence (verified 2026-08-17)
1. `/health` (async, rate-limit-exempt, unauthenticated) → blocking `smtplib.SMTP(timeout=5)`, `os.statvfs`, DB probes, 3-4 INSERTs per call (health.py:62-74, _orchestrator_health.py:90-126) — anonymous parallel GETs starve the loop 5s at a time + bloat health_checks unboundedly.
2. Process-wide DB mutex: every `execute()` serializes on one lock (manager.py:156,192; pools.py:21-23 ponytail); `acquire()` runs `SELECT 1` inside the lock; async deps/handlers call it directly (deps.py:24,38,80; dashboard.py:25-35). Correlation persistence COUNT(*) before/after per event = O(n²) under the lock.
3. Audit middleware re-validates token/key on-loop per request (audit.py:143,150) — double the revocation DB hit deps already pays.
4. Restore swap race: new acquires can slip in around the file swap (backup.py:258-266 — hold `db._lock` for the swap).

## Deliverables
1. /health: cached response + SMTP probe off-loop + insert-on-interval, not per-request; body-cap middleware reused.
2. Sync `def` deps (threadpool dispatch) or to_thread for DB in async paths; audit middleware reuses the deps validation result instead of re-validating.
3. Scoped locking for read paths (per-connection or read-write lock); persistence COUNT under one statement.
4. Restore swap under db._lock.
