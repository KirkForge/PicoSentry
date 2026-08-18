# WO6.0.0-010 — Serve: persistence failure contracts — rate-limit flush catches the wrong exception class (500s on every request) + /run orphaned rows

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/persistence-contracts`)
**Priority:** P0 · Effort M · Risk M
**Scope:** `picosentry/serve/middleware/rate_limit.py`, `picosentry/serve/services/event_bus.py` (`_persist_outbox`), `picosentry/serve/services/orchestrator.py` (publish placement), `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + tests: flush/sync under a held write lock does NOT raise (request completes; memory-only degradation per the documented contract); publish under a held lock does not orphan a `project_runs` row.

## Objective
`sqlite3.OperationalError` (the exact error busy_timeout=15s produces) is a subclass of NEITHER `OSError` NOR `ValueError` — three "best-effort" persistence paths catch the wrong tuple and turn DB contention into request failures.

## Evidence (verified 2026-08-18, explorer SA-AU; repro /tmp/opencode/sa-au/repro_flush_uncaught.py)
1. **Rate-limit flush** (`rate_limit.py:152-186`): `except (OSError, ValueError)`; the flush runs inside `self._lock` on the REQUEST path (`_record_and_check` → `_evict_if_needed`, `:284-292`, before `call_next`) — a busy-timeout expiry becomes a 500 after a 15s stall on EVERY request while any long writer (chunked audit purge, another worker's per-bucket flush loop) holds the DB. Live: `REPRODUCED: _record_and_check raises database is locked -> request 500s`.
2. **Outbox persist sibling** (`event_bus.py:160`): same wrong tuple despite the "best-effort… local delivery must not be lost" docstring — OperationalError propagates out of `publish()`; in `_execute_project` the started-event publish (`orchestrator.py:275`) sits BEFORE the try block → `/run` 500s and the `project_runs` row (`:267`) is orphaned `'running'` forever. (The scheduler path survives — `_JOB_EXECUTE_ERRORS` correctly includes `sqlite3.Error`, `scheduler.py:49-57`.)
3. **Flush under the middleware lock** is O(active-buckets) long (SELECT+upsert per bucket, max_buckets=100000) + `_sync_from_db` re-reads the table — cross-worker contention serializes every request on a worker behind it.

## Deliverables
1. Correct exception classes (`sqlite3.Error` + `psycopg2.Error`) in flush/sync/outbox-persist; degrade to memory-only per contract.
2. Move the flush off the request path (background cadence thread; snapshot buckets under the lock, transact outside); cap flush batch; `ponytail:` ceiling for max_buckets↔flush-length.
3. Move the started-event publish inside the guarded section (or tolerate publish failure without orphaning the run row).
4. Regression tests per the gate (held-write-lock fixtures).
