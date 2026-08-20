# WO7.0.0-028 — Serve: `acknowledge_alert` conflates "acknowledged" with "delivered" via `sent` column

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/acknowledge-alert-flag`)
**Priority:** P1 · Effort S · Risk L
**Scope:** `picosentry/serve/api/routers/projects.py`, `picosentry/serve/database/_schema.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + test: an acknowledged-but-not-delivered alert has `acknowledged=1, sent=0`; the two flags are independently settable and queryable.

## Objective
`acknowledge` sets `sent = 1` (a delivery flag) instead of an `acknowledged` flag. Acknowledged alerts look delivered; delivery reports are wrong.

## Evidence (verified 2026-08-20, explorer SA-serve; file:line chain)
- `projects.py:206-214`: `acknowledge_alert` issues `UPDATE ... SET sent = 1 WHERE id = ?`.
- No `acknowledged` column exists on the alerts table.

## Deliverables
1. Add `acknowledged BOOLEAN DEFAULT 0` column (migration 24); `acknowledge_alert` sets `acknowledged = 1` (not `sent`).
2. Regression test per the gate (independent flags).