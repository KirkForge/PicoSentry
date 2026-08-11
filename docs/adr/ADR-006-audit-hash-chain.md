# ADR-006: Tamper-evident audit hash-chain in the serve middleware

**Status:** Accepted
**Date:** 2026-08

## Context

The serve API records every request to an `audit_log` table so operators can
reconstruct who did what. A plain append-only log is not tamper-evident: an
attacker with write access to the database can edit or delete rows without
leaving a trace. The audit middleware (`picosentry/serve/middleware/audit.py`)
needs a way to make retroactive modification detectable.

## Decision

Each audit row carries two hash columns, `prev_hash` and `row_hash`, forming a
hash chain:

- `row_hash = sha256(prev_hash | method | user_id | path | details_json | ip)`
  where `details_json` is the canonical `json.dumps(details, sort_keys=True)`
  of the request metadata (method, path, query, status code, duration).
- `prev_hash` of row *N* equals `row_hash` of row *N-1*, so every row is bound
  to its predecessor. Editing any row breaks the chain at that point and every
  subsequent row.
- The chain head is held in memory (`_AuditChain.prev_hash`) and updated after
  each insert, under a process-wide `_audit_lock` so concurrent requests cannot
  interleave and corrupt the linkage.

Because the chain is in-memory only, a process restart would otherwise make the
first post-restart row link to `prev_hash=""` even though the last committed
row has a non-empty `row_hash` — silently breaking tamper-evidence across
restarts. To close that gap, `_seed_chain(db)` runs on the first write after
startup (inside the lock) and reads the last committed `row_hash`
(`SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1`) to resume the
chain from the persisted head.

## Rationale

- **Detectable tampering:** any edit to a committed row invalidates the hash
  of that row and every later row, so a verifier can detect retroactive
  modification without a trusted third party.
- **No external dependency:** the chain is self-contained in the audit table;
  no HSM, signing service, or append-only store is required.
- **Restart reseed is cheap and correct:** one indexed `ORDER BY id DESC
  LIMIT 1` lookup on first write, guarded by the same lock as the insert, so
  the in-memory head always matches the persisted head.
- **Deterministic canonical form:** `sort_keys=True` on the details JSON makes
  the hash reproducible regardless of dict insertion order.

## Consequences

- The audit table is append-only in practice; deleting or editing a row is
  detectable but not prevented. A verifier must recompute the chain to detect
  tampering — the middleware does not currently expose a verification endpoint.
- The chain is not cryptographically signed; it proves *internal consistency*
  (rows link to each other), not *authenticity* (that the writer was the
  legitimate server). An attacker who can rewrite the whole table can rebuild a
  consistent chain.
- `_seed_chain` silently skips (returns) if the DB read fails, so a transient
  DB error at startup degrades to the pre-restart behavior rather than
  crashing the request path.
- The `org_id` column is written as `NULL` for every audit row; org attribution
  is not yet part of the chain input.
