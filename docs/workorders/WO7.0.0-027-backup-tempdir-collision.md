# WO7.0.0-027 — Serve: `backup.create_backup` temp_dir collision under concurrency

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/backup-tempdir-collision`)
**Priority:** P1 · Effort S · Risk L
**Scope:** `picosentry/serve/services/backup.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + test: two concurrent `create_backup` calls in the same second use distinct temp dirs and both succeed.

## Objective
`temp_dir = f"temp_{timestamp}"` — two backups in the same second share a dir, clobbering each other's files.

## Evidence (verified 2026-08-20, explorer SA-serve; file:line chain)
- `backup.py:132-133`: `temp_dir = f"temp_{timestamp}"` with second-granularity timestamp.
- Concurrent backups (scheduler + manual) in the same second collide.

## Deliverables
1. Append a `uuid4().hex` suffix to `temp_dir`.
2. Regression test per the gate.