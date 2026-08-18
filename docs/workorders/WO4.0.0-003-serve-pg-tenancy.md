# WO4.0.0-003 — Serve: Postgres tenancy correctness

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** DONE (PARTIAL 2026-08-17 → complete 2026-08-18: the missing green pg-live CI job arrived with the WO4-017 dbname fix and the pg-live burn-down — postgres 15/16/17/18 legs green in every push since, incl. runs 32137930302/32139357333). Landed & wired: Organization.create via execute_on (orgs.py:29-43), portable ON CONFLICT DO NOTHING upsert + migration 18 (orgs.py:131-141), auth/correlation raw-`?` sites converted, no INSERT OR IGNORE left in picosentry/serve/, org-flow tests (7)
**Owner:** (unassigned — worktree `wo/4.0.0/pg-tenancy`)
**Priority:** P0 · Effort S-M · Risk L
**Scope:** `picosentry/serve/services/orgs.py`, `picosentry/serve/database/manager.py`, `.github/workflows/ci.yml` (postgres job), `scripts/live_test_postgres.sh`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + postgres-live CI job extended from smoke script to the serve org-flow suite, green.

## Objective
Org creation and org-project association are broken on postgres; make the whole org surface run on both backends and prove it in CI.

## Evidence (verified 2026-08-17)
1. `orgs.py:27-42` `Organization.create()` runs raw `conn.execute("... VALUES (?, ...)")` inside `db.transaction()` — `transaction()` yields the raw connection without `_prepare_sql` (manager.py:79-106) → `?` is a postgres syntax error, swallowed by `except Exception: return None` → router answers a misleading 409.
2. `orgs.py:133-139` `add_project` uses SQLite-only `INSERT OR IGNORE` → psycopg2 ProgrammingError on **every org-stamped run's success path** (orchestrator.py:390-391), outside the router's caught exception tuple → 500 after the run row commits.
3. CI postgres-live job is a 40-line smoke script (table presence + one alerts CRUD) — both breaks invisible.

## Deliverables
1. `Organization.create` via `execute_on` (placeholder translation); dialect-aware upsert for `add_project`.
2. Audit remaining raw-`conn.execute` / SQLite-ism sites repo-wide (grep `INSERT OR IGNORE`, `?` inside `transaction()`).
3. Extend the pg CI job to run the serve integration suite against postgres (env-pointed DB), not a smoke script.
