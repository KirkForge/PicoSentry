# WO7.0.0-033 — Serve: `_orchestrator_health.perform_health_checks` writes rows non-atomically

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/orchestrator-health-atomic`)
**Priority:** P2 · Effort S · Risk L
**Scope:** `picosentry/serve/services/_orchestrator_health.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + test: a crash mid-`perform_health_checks` leaves no partial snapshot (all-or-nothing); the health table reflects the last fully-written snapshot.

## Objective
Each INSERT in `perform_health_checks` is a separate autocommit — a crash mid-loop leaves a partial snapshot. Health dashboards can show inconsistent subsystem states.

## Evidence (verified 2026-08-20, explorer SA-serve; file:line chain)
- `_orchestrator_health.py:167-186`: one `INSERT` per subsystem, each in its own autocommit transaction.

## Deliverables
1. Wrap the loop in one transaction (commit once at the end; rollback on any failure).
2. Regression test per the gate (inject a mid-loop failure, assert no partial rows).