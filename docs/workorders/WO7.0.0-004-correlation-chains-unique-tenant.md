# WO7.0.0-004 — Serve: `correlation_chains.artifact_id UNIQUE` clobbers cross-tenant chain scores

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/correlation-chains-unique`)
**Priority:** P0 · Effort S · Risk M
**Scope:** `picosentry/serve/database/_schema.py`, `picosentry/serve/services/correlation/persistence.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + test: two orgs ingesting the same artifact get independent cached chain rows; neither UPDATE overwrites the other's `org_id` or `chain_score`.

## Objective
`correlation_chains.artifact_id TEXT UNIQUE NOT NULL` collapses two orgs ingesting the same artifact into ONE cached row. The SQLite UPDATE path overwrites `chain_score` WITHOUT updating `org_id` — cross-tenant leak + lost scores.

## Evidence (verified 2026-08-20, explorer SA-serve; file:line chain)
- `_schema.py:576`: `artifact_id TEXT UNIQUE NOT NULL` (table definition).
- `_schema.py:616`: index definition repeats the unique constraint.
- `persistence.py:154-156`: `UPDATE correlation_chains SET chain_score = ?, ... WHERE artifact_id = ?` — no `org_id` in SET, no `org_id` in WHERE; second org's write clobbers the first's score while leaving the first's `org_id`.

## Deliverables
1. Schema migration 24: drop the bare `UNIQUE` on `artifact_id`, add `UNIQUE(org_id, artifact_id)`.
2. `UPDATE` SET clause includes `org_id`; WHERE clause is `(org_id, artifact_id)`.
3. Regression test per the gate.