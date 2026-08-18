# WO6.0.0-022 — Docs: manual P2-wave rider (X-Org-Id, members/quotas, multi-worker honesty, rotation announcements)

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/manual-p2-rider`)
**Priority:** P1 · Effort S-M · Risk L
**Scope:** `docs/manual.md` (verify claims against code first), `tests/` lockstep if version lines are touched

**Gate:** `bash scripts/test.sh fast` + every new/changed claim verified against code (grep the symbol); lockstep tests green.

## Objective
The manual (pinned at the P1 base + P1 riders) is stale against the P2 wave — and one recommendation currently trips real bugs.

## Evidence (2026-08-18, explorer SA-AU F5 + SA-AT)
- `manual.md:3049-3051` documents org scoping via `X-Org-API-Key` only — `X-Org-Id` (WO5-032) is documented NOWHERE in the manual.
- No mention of `POST/PATCH/DELETE /orgs/{id}/members`, `GET /orgs/{id}/usage`, tier quotas, or the 402 contract.
- `manual.md:313` recommends `--workers 4 # production` with no WO5-031 ceilings — and WO6-009/010 mean that recommendation currently trips the N×-escalation and poller bugs. Reword honestly ("multi-worker: core landed, e2e pending; see limitations") until those land.
- Cluster rotation section (`:1925-1946`) documents the CLI flow but not announcement semantics (HMAC-derived primary, ANY-MEMBER adoption, grace behavior, self-refresh caveat pending WO6-014).
- Watch CLI `--picoshogun-plugin` unreachable standalone (`cli.py:181-186` — flag checked after the None-command exit): fix the code (1-line reorder, watch tree) or document; prefer the fix, coordinate with any watch worker.

## Deliverables
Manual rider sections; claims code-verified; the `--workers 4` wording made honest; plugin-flag 1-line fix (or documented).
