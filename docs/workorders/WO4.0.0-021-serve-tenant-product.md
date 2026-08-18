# WO4.0.0-021 — Serve: multi-tenant product completeness

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** CLOSED-FOLDED (2026-08-18) — remainder (tier enforcement quotas, member mgmt endpoints, org-switch header, pagination, plugin capability decision) moved to **WO5.0.0-032**. Landed & shipped in v2.1.2: unsigned bundled plugin no longer auto-loads (bundled dir requires signature — `tests/serve/test_plugin_auto_load.py`); run-output bounding (`_bounded`, 100k + truncated flag — `tests/serve/services/test_orchestrator.py::TestRunOutputBounding`)
**Owner:** worker subagent (worktree `wo/4.0.0/serve-p1`)
**Priority:** P2 · Effort L · Risk M
**Scope:** `picosentry/serve/services/{orgs.py,orchestrator.py}`, `picosentry/serve/api/{routers,models}.py`, `picosentry/serve/plugins/**` (phase-1 capability enforcement)

**Gate:** `bash scripts/test.sh fast` + quota tests (tier limits enforced on run/create/member-add) + plugin unsigned-default-load removed. — fast GREEN; plugin part MET; quota part NOT MET

## Objective
Make the org model a usable product surface: enforced tiers, member management, pagination, first-phase plugin capability enforcement.

## Evidence (verified 2026-08-17)
1. Tiers are display-only: `TIERS`/`get_usage` reported, ZERO enforcement anywhere (verified by grep) — no run/project/member limits.
2. `OrgMemberInviteRequest` model exists with no endpoint (models.py:186) — members can't be invited/removed/role-changed; `ADMIN_USERS` permission unused — no user-management API.
3. No offset/cursor pagination (LIMIT-only, le=200); multi-org JWT users locked to first org (deps.py:109, no org-switch header); `project_runs.output` stores full stdout unbounded (orchestrator.py:296-315).
4. Plugin trust boundary is env-strip only: capabilities `network/filesystem/subprocess` declared-but-unenforced (plugin_manager.py:40-46); the UNSIGNED `test_discord_notifier` auto-loads in every deployment (plugin_manager.py:152,564) spawning a subprocess that receives alert payloads.

## Deliverables
1. Tier enforcement (runs_per_day, members, projects; storage definition) with quota-exceeded errors. — NOT DONE
2. Member invite/remove/role endpoints (dead model), org-switch header, offset pagination. — NOT DONE
3. Plugin phase-1: drop unsigned bundled plugin from default load (DONE — bundled dir requires signature, user dirs unaffected); capability enforcement decision (seccomp/landlock reuse from picodome) — full enforcement can be its own follow-up (NOT DONE, no decision recorded yet).
4. Run-output bounding (truncate + flag). — DONE
