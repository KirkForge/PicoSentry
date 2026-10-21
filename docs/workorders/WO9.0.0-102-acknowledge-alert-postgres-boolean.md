# WO9.0.0-102 — Serve: `acknowledge_alert` uses `acknowledged = 1` integer literal → breaks on Postgres (boolean column)

**Series:** WO9.0.0 (audit round 2026-08-23)
**Status:** DONE (2026-10-21, worktree `wo/9.0.0/p0-cluster`) — `acknowledged` was missing from _BOOL_LITERAL_RE, so `UPDATE alerts SET acknowledged = 1` reached postgres as an integer literal against a BOOLEAN column and the acknowledge endpoint 500'd on every Postgres deployment. `acknowledged` is now in the translator (with a comment that the list must track the BOOLEAN columns in _schema.py) AND the call site uses the portable `= TRUE` form, so the write is correct without relying on the translator. Systemic rider: the acknowledge test file is now in the postgres-live CI job — boolean-column writes are only exercised against a real postgres, which is why this shipped broken for two releases — and a guard test in tests/test_ci_paths.py pins that membership. Evidence: tests/serve/test_db_postgres_commit.py (20 passed; new acknowledged = 1 / = 0 translation tests).
**Owner:** (unassigned)
**Priority:** P0 · Effort S · Risk L
**Scope:** `picosentry/serve/database/manager.py`, `picosentry/serve/api/routers/projects.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + test: `POST /alerts/{id}/acknowledge` succeeds on the Postgres backend (boolean column accepts the value, no `operator does not exist` error).

## Objective
The `acknowledge_alert` endpoint (`projects.py:213`) executes `UPDATE alerts SET acknowledged = 1 WHERE id = ?`. The `acknowledged` column is `BOOLEAN` on Postgres (migration 25, `_schema.py:1108`). The runtime SQL boolean-literal translator `_BOOL_LITERAL_RE` (`manager.py:34`) only translates `is_active|active|sent|enabled` — it does NOT include `acknowledged`. So on Postgres, `acknowledged = 1` is sent to the server as `acknowledged = 1` (integer literal against a BOOLEAN column), raising `operator does not exist: boolean = integer`. The `POST /alerts/{id}/acknowledge` endpoint returns 500 on every Postgres deployment. This is a regression from WO7.0.0-028 (which added the `acknowledged` column) and WO8.0.0-108 (which fixed the `pending_alerts` query to `IS NOT TRUE` but missed the write path).

## Evidence (verified 2026-08-23, explorer; live repro + airtight file:line chain)
- `_schema.py:1108`: `ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged BOOLEAN DEFAULT FALSE;` — Postgres column is BOOLEAN.
- `projects.py:213`: `db.execute_insert("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))` — integer literal `1`.
- `manager.py:34`: `_BOOL_LITERAL_RE = re.compile(r"\b(is_active|active|sent|enabled)(\s*[=!<>]+\s*)([01])\b")` — `acknowledged` is NOT in the alternation.
- `manager.py:110`: `sql = _BOOL_LITERAL_RE.sub(...)` — only the four listed columns are translated; `acknowledged = 1` passes through untranslated.
- Live repro (`/tmp/opencode/test_ack_bool.py`):
  ```
  Original: UPDATE alerts SET acknowledged = 1 WHERE id = ?
  Prepared: UPDATE alerts SET acknowledged = 1 WHERE id = ?   # NOT translated
  acknowledged translated? False
  Would fail on Postgres BOOLEAN column? True
  ```
- Contrast: `orchestrator.py:147` and `dashboard.py:40` use `acknowledged IS NOT TRUE` (the proper portable form), which works on both backends. Only `projects.py:213` uses the broken integer literal.

## Deliverables
1. Add `acknowledged` to the `_BOOL_LITERAL_RE` alternation in `manager.py:34`: `r"\b(is_active|active|sent|enabled|acknowledged)(\s*[=!<>]+\s*)([01])\b"`.
2. Alternatively (or in addition), change `projects.py:213` to use the portable `IS NOT TRUE` / `= TRUE` form: `UPDATE alerts SET acknowledged = TRUE WHERE id = ?` — but the regex fix is the systemic fix (catches any future `acknowledged = 1` writes too).
3. Regression test per the gate (run the acknowledge endpoint against the Postgres backend in the `postgres-live-test` CI job).