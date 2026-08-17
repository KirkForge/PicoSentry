# WO4.0.0-013 — Serve: concurrency & event-loop hygiene

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** DONE 2026-08-17 (worktree `wo/4.0.0/serve-p1`) — evidence: `tests/serve/test_health_offloop.py` (starvation regression + cache/insert-on-interval + retention), `tests/serve/test_db_rwlock.py` (RW lock semantics, statement scoping, concurrent reads+writes), `tests/serve/test_security_review.py::TestAuditMiddlewareHardening`
**Owner:** worker subagent (worktree `wo/4.0.0/serve-p1`)
**Priority:** P1 · Effort M-L · Risk M
**Scope:** `picosentry/serve/api/deps.py`, `picosentry/serve/middleware/{audit.py,request_size_limit.py}`, `picosentry/serve/api/routers/health.py`, `picosentry/serve/services/_orchestrator_health.py`, `picosentry/serve/services/{backup.py,correlation/persistence.py}`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + a loop-blocking regression test (no handler-starvation > N ms under parallel /health + DB reads). — GREEN

## Resolution notes
1. `/health`: 15s TTL cache with single-flight (probe under one lock), probe runs via `asyncio.to_thread` → SMTP/DB/disk probes never on the loop; inserts now per-probe (interval), not per-request; `health_checks` retention trim (keeps newest 1000, guarded so a trim failure never fails the probe). `/status` + `/dashboard/summary` DB reads also moved to `to_thread`.
2. Deps `get_current_user`/`get_current_org`/`require_role`/`require_permission` inner checks are now sync `def` → FastAPI threadpool. Audit middleware reuses the deps result via `request.state.picoshogun_auth`/`picoshogun_org` (zero validator calls on authed endpoints — pinned by `test_middleware_skips_revalidation_when_deps_ran`); the fallback re-validation only runs for requests no dep authenticated (404 probe traffic), off-loop via `to_thread` (org-stamping for unmatched routes preserved — `test_audit_lifecycle.py` green).
3. `DatabaseManager._lock` is now a writer-preferring `ReadWriteLock` (pools.py): SELECT/PRAGMA/EXPLAIN share, everything else (incl. unrecognized SQL) is exclusive. `backup()` holds the write half around `sqlite3.backup`. Migration to writer-preferring validated by dedicated lock tests.
4. Restore swap (backup.py) runs under `db._lock.write()` — in-flight statements drain and new ones block during close/wal-drop/copy/swap.
5. Correlation persistence: COUNT(*)-before/after per event replaced by an indexed dedup-key existence probe (O(n²) → O(log n) per event).

## Known limitation (deliberate, ponytail)
Audit-writer chain serialization still relies on sqlite-level `BEGIN IMMEDIATE` + busy timeout (unchanged); cross-process writer coordination is WO-020 territory.
