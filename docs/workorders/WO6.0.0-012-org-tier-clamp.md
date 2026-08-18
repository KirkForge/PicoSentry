# WO6.0.0-012 — Serve: org create honors client-supplied `tier` — any viewer self-serves enterprise (unlimited quotas)

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/org-tier-clamp`)
**Priority:** P0 · Effort S · Risk L
**Scope:** `picosentry/serve/api/routers/orgs.py`, `picosentry/serve/api/models.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + test: viewer-created org is `free`; only global admin can create a paid tier (mirroring the `/upgrade` dual gate); quotas follow.

## Objective
WO5-032 made tiers the quota ceiling — and left the front door open.

## Evidence (verified 2026-08-18, explorer SA-AR; live repro)
Fresh registered user (default role `viewer`): `POST /orgs` with `tier=enterprise` → **201 tier=enterprise** (999 members / 99999 runs/day). The router (`orgs.py:50-74`) gates only on `get_current_user`; meanwhile `POST /orgs/{id}/upgrade` requires global admin + org admin (`:156-164`) — create-with-tier bypasses exactly that control. Either a bug or an undocumented product decision; clamp is the safe default.

## Deliverables
1. Clamp create to `free` unless caller is global admin (or document self-service-tier as an explicit product decision in the manual — pick with the owner; default to clamp).
2. Regression test per the gate.
