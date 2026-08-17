# WO4.0.0-004 — Serve: audit lifecycle (retention × tamper-evidence)

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** DONE (verified 2026-08-17, shipped in v2.1.2 — gap-tolerant verify + chained audit.purge markers (audit_chain.py:102-110,158-162; audit_cleanup.py:37-61,152-155), org_id stamped on rows at write (audit_chain.py:60,79,92), AuditMiddleware outermost so 429/413/DDoS-blocked requests are audited (api/server.py:354-358), drop counters wired into /metrics gauges + verify endpoint (middleware/audit.py:67, correlation/engine.py:97, routers/admin.py:84-85); ADR-006 addendum)
**Owner:** (unassigned — worktree `wo/4.0.0/audit-lifecycle`)
**Priority:** P0 · Effort M · Risk M
**Scope:** `picosentry/serve/services/{audit_cleanup.py,audit_chain.py}`, `picosentry/serve/middleware/audit.py`, `picosentry/serve/services/{correlation/engine.py,metrics.py}`, `docs/adr/ADR-006` addendum, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + new interaction tests: purge-then-verify passes; audit rows carry org_id; blocked (429/504) requests audited; drop counters exported.

## Objective
Retention and verification must coexist — today the first scheduled purge permanently breaks the chain verifier, audit rows are org-blind, and blocked requests are unaudited.

## Evidence (verified 2026-08-17)
1. `audit_cleanup.py:33,49-52` deletes by severity/cutoff while `audit_chain.py:127-148` checks each row's `prev_hash` against the nearest *surviving* predecessor → first scheduled cleanup (6h cron) makes `GET /admin/audit/verify` report "fork or deleted link" forever. The two features landed the same day, tested separately, never together.
2. `audit.py:188` hardcodes `org_id: None` — org-filtered audit stats/purge see nothing.
3. Middleware order puts Audit innermost → 429/413/DDoS-blocked requests never reach the tamper-evident log; attack evidence lives only in plain logs.
4. Drop counters (audit writer `dropped`, correlation engine drops) confirmed unwired into any metric.

## Deliverables
1. Pick one (ADR-006 addendum): tail-contiguous purge (delete only suffix runs) OR gap-tolerant verify + periodic anchor checkpoint.
2. Org_id on audit rows at write time.
3. Audit the blocked-request paths (move Audit outermost or add a blocked-request audit record).
4. Wire `dropped_audit_records` (serve + watch) into /metrics and the verify endpoint status.
