# WO7.0.0-018 — Sandbox: daemon restart leaves orphaned "running" jobs — no startup reconciliation

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/daemon-orphan-reconcile`)
**Priority:** P1 · Effort S · Risk L
**Scope:** `picosentry/sandbox/daemon/daemon.py`, `picosentry/sandbox/daemon/{store.py,sqlite_store.py,redis_store.py}`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + test: a daemon with 2 "running" + 1 "queued" job at start marks them failed with an orphan error; no "running" row survives startup.

## Objective
`__init__` never scans for stale "running"/"queued" jobs. A crash mid-scan leaves the job "running" forever — clients polling never see a terminal state.

## Evidence (verified 2026-08-20, explorer SA-sandbox; file:line chain)
- `daemon.py:32-141`: `__init__` boots stores and executors but does no reconciliation.
- `store.py`/`sqlite_store.py`/`redis_store.py`: no `reconcile_on_start` or equivalent method; stale rows persist.

## Deliverables
1. On start, scan for `status IN ("running", "queued")` rows and mark them failed with an orphan error (e.g. `ORPHANED_ON_RESTART`).
2. Regression test per the gate (across all three store backends).