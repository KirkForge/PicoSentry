# WO7.0.0-005 — Serve: `update_project_stats` counts ALL orgs' runs for a shared project (cross-tenant leak)

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/project-stats-tenant-filter`)
**Priority:** P0 · Effort S · Risk M
**Scope:** `picosentry/serve/services/_orchestrator_stats.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + test: a shared/global project's `run_count` for org A reflects only org A's runs after org B ingests the same project.

## Objective
`update_project_stats` runs `SELECT COUNT(*) FROM project_runs WHERE project_id = ?` with NO `org_id` filter. For shared/global projects, every org's runs blend into one count — cross-tenant leak in stats and dashboards.

## Evidence (verified 2026-08-20, explorer SA-serve; file:line chain)
- `_orchestrator_stats.py:27-55`: the SELECT has only `project_id = ?` in the WHERE clause; `org_id` is available in the table but never filtered.
- The function writes the blended count back into the per-project stats row.

## Deliverables
1. Add `AND org_id = ?` to the SELECT (and any sibling SELECT in the same function); pass the caller's `org_id`.
2. Regression test per the gate (two orgs, shared project, counts independent).