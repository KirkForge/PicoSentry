# WO7.0.0-025 — CI: gitlab template github-format hard-fails (action.yml fixed in WO6-021, gitlab not updated)

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/gitlab-template-github`)
**Priority:** P1 · Effort S · Risk L
**Scope:** `ci-templates/gitlab-picosentry.yml`, `tests/ci_templates/`

**Gate:** `bash scripts/test.sh fast` + teeth test: gitlab template invoking the `github` format passes `--sarif-file` (not `--output`); the rendered command is asserted.

## Objective
The gitlab template passes `--output` for all formats; the github format needs `--sarif-file`. WO6-021 fixed `action.yml` for the same bug but the gitlab template was not updated — github-format users on gitlab get a hard fail.

## Evidence (verified 2026-08-20, explorer SA-core; file:line chain)
- `ci-templates/gitlab-picosentry.yml:13,30-46`: unconditional `--output` for every format including `github`.
- The github format requires `--sarif-file` (per WO6-021's fix to `action.yml`).

## Deliverables
1. Route the `github` format to `--sarif-file` in the gitlab template (mirror the `action.yml` fix).
2. Teeth test per the gate (rendered command asserted).