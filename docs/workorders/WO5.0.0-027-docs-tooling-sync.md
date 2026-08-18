# WO5.0.0-027 — Docs & tooling sync sweep (small truthfulness riders)

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/docs-sync`)
**Priority:** P2 · Effort S · Risk L
**Scope:** `.env.example`, `docs/OFFLINE.md`, `scripts/{verify_release.py,test_doctor.py,post_pr_comment.py}`, `picosentry/experimental.py`, `picosentry/scan/_engine_scan_helpers.py`, `picosentry/serve/services/orgs.py`, `picosentry/serve/config/settings.py`, `pyproject.toml`, `tests/`

**Gate:** `bash scripts/test.sh fast` + a venv-project stats test (packages_scanned > 0 for `venv/` layout); org-create internal-failure no longer reports "slug already exists".

## Objective
Rider batch of small doc-rot and dead-tooling items plus two tiny code fixes found by the round.

## Evidence (verified 2026-08-18, explorer SA-R/SA-T/SA-V)
1. **`.env.example` says SSL env vars are never read — they are** (`.env.example:45-50` vs `settings.py:112-113,249`): code fixed 2026-08-17, comment survived; boot-check even instructs using the env var. Under-claiming doc rot.
2. **OFFLINE.md claims `picosentry advisories` "is not a unified-CLI subcommand" — it is** (`OFFLINE.md:33-38` vs `cli_commands/scan.py:111` + live `--help`).
3. **`scripts/verify_release.py:14-15` usage hint uses invalid predicate type** `slsaprovenance`; working form is the full URI (used by verify-release.yml:63). Copy-paste fails.
4. **`scripts/test_doctor.py` claims to mirror CI** ("CI matrix runs this serially (no xdist)") but CI runs `scripts/test.sh` profiles with xdist; the script bypasses the profile system with inline pytest args.
5. **`scripts/post_pr_comment.py` referenced by nothing** (consumer removed in the CI-dedup round) — delete or rewire.
6. **`experimental.py:92` "live PG 15/16 CI"** — matrix is 15/16/17/18.
7. **pyproject coverage omits `picosentry/_cli_commands/*`** — directory doesn't exist (package is `cli_commands`); dead config from a rename.
8. **`count_installed_packages` counts only `.venv`** (`_engine_scan_helpers.py:101`) while detection and the rule layer support `venv/` and `.tox/` (`pypi_utils.py:22-27`, `engine.py:119`) — plain-`venv/` projects report `packages_scanned: 0` (stats lie for the exact shape WO-015 fixed).
9. **`Organization.create` error conflation** (`orgs.py:22-57`): `{}` for slug-taken, `None` for internal failure; router maps both to 409 "slug already exists" — DB failures misreported.
10. **Env-var naming inconsistency**: `DISCORD_WEBHOOK_URL`/`SLACK_WEBHOOK_URL` read without the `PICOSHOGUN_` prefix every other knob uses (`settings.py:174-175`).

## Deliverables
Fix all ten; each is one-to-few lines. Update docs-claim tests where they exist.
