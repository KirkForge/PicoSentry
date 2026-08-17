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
  detectable but not prevented. ~~A verifier must recompute the chain to detect
  tampering — the middleware does not currently expose a verification endpoint.~~
  **Update (2026-08):** a verifier now exists — `GET /audit/verify`
  (`picosentry/serve/api/routers/admin.py`) recomputes the chain via
  `verify_audit_chain()` (`picosentry/serve/services/audit_chain.py`) and
  reports the first break. The chain is also anchored to the DB head on
  restart so the pre-restart link is preserved.
- The chain is not cryptographically signed; it proves *internal consistency*
  (rows link to each other), not *authenticity* (that the writer was the
  legitimate server). An attacker who can rewrite the whole table can rebuild a
  consistent chain.
- `_seed_chain` silently skips (returns) if the DB read fails, so a transient
  DB error at startup degrades to the pre-restart behavior rather than
  crashing the request path.
- The `org_id` column is written as `NULL` for every audit row; org attribution
  is not yet part of the chain input.

## Addendum (2026-08, WO4.0.0-004): retention × tamper-evidence

### Context

Retention purges (`audit_cleanup.purge_audit_logs`, severity-tiered and
bulk) delete rows from the middle of the chain, but the verifier compared
each row's `prev_hash` to its nearest *surviving* predecessor — the first
scheduled purge made `GET /admin/audit/verify` report "fork or deleted link"
forever. The two features shipped the same day and were only tested
separately.

### Decision: gap-tolerant verify with purge-time gap markers

We reject tail-contiguous purge (only deleting suffix runs): a critical row
that is one day past its cutoff would pin every earlier row of every
severity forever, because anything before it must survive to keep the chain
linked — the documented retention policy becomes unenforceable exactly for
the severities that matter most. Instead, **purges record what they
deleted, and the verifier accepts those recorded gaps**:

- `purge_audit_logs` selects the exact ids it will delete, deletes them
  inside one write transaction, and appends a chained `audit.purge` row
  (severity=`critical`, so the marker outlives every retention class it can
  describe) whose `details` carry the deleted ids as contiguous runs,
  e.g. `{"deleted": 12, "gaps": [[41, 44], [97, 104]]}`.
- `verify_audit_chain` builds the purged-id set from all `audit.purge` rows
  and treats a `prev_hash` mismatch as an authorized gap iff every id
  between the two surviving rows is in that set (for the head of the table:
  iff the entire id prefix below the row is). Each row's own `row_hash`
  recomputation is unchanged, so field tampering of any surviving row is
  still detected.
- Forging a gap marker requires inserting a chained row, which requires
  rebuilding the chain tail — the same barrier as any full-rewrite attack
  already documented below (internal consistency, not authenticity).

Residual ceiling (ponytail: accepted): the gap markers are themselves
retained 365d (critical tier). A marker purged at end-of-life while younger
surviving rows still link across its gap would surface as an unexplained
break; if that horizon is ever hit in practice, compact markers during
purge instead of deleting them.

### Consequences (2026-08)

- Purge → verify interaction is now a tested pair, not two features.
- Blocked requests (429 rate-limit, 413 size-limit, DDoS shield, 504
  timeout) are audited: `AuditMiddleware` is now registered outermost, and
  the request id from `RequestIDMiddleware` is copied into the row's
  `details`, so attack evidence in the tamper-evident log correlates with
  the structured log lines.
- Audit rows carry `org_id` at write time (API key scope, `X-Org-API-Key`,
  or the JWT `org_id` claim stamped at login — best-effort attribution;
  enforcement in `deps.get_current_org` always re-resolves membership).
- Audit-writer queue drops and correlation-engine backpressure drops are
  exported as instance-wide gauges (`picoshogun_dropped_audit_records`,
  `picoshogun_dropped_correlation_events`) and surfaced on the verify
  endpoint, so silent evidence loss is observable.
