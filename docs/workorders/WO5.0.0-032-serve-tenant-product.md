# WO5.0.0-032 — Serve: tenant product completeness (folds WO4.0.0-021 remainder)

**Series:** WO5.0.0 (fold 2026-08-18 from WO4.0.0-021 PARTIAL)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/serve-tenant-product`)
**Priority:** P2 · Effort L · Risk M
**Scope:** `picosentry/serve/services/{orgs.py,orchestrator.py}`, `picosentry/serve/api/{routers,models}.py`, `picosentry/serve/plugins/**`

**Gate:** `bash scripts/test.sh fast` + quota tests (tier limits enforced on run/create/member-add with quota-exceeded errors) + member lifecycle test + org-switch header test.

## Objective
Make the org model a usable product surface: enforced tiers, member management, pagination.

## Evidence (carried, verified 2026-08-17; unsigned-plugin auto-load + run-output bounding already DONE in WO4)
1. Tiers display-only: `TIERS`/`get_usage` reported, zero enforcement (no run/project/member limits).
2. `OrgMemberInviteRequest` model exists with no endpoint (models.py:186) — members can't be invited/removed/role-changed; `ADMIN_USERS` permission unused.
3. No offset/cursor pagination (LIMIT-only, le=200); multi-org JWT users locked to first org (deps.py:109, no org-switch header).
4. Plugin capability enforcement decision still unrecorded (phase-1: seccomp/landlock reuse from picodome vs declared-only).

## Deliverables
1. Tier enforcement (runs_per_day, members, projects) with quota-exceeded errors.
2. Member invite/remove/role endpoints (wire the dead model), org-switch header, offset pagination.
3. Plugin capability decision recorded (ADR note) — enforcement itself may be a follow-up.
