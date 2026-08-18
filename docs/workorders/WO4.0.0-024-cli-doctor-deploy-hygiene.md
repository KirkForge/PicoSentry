# WO4.0.0-024 — CLI/doctor/deploy hygiene (riders)

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** CLOSED-FOLDED (2026-08-18, never dispatched as a unit) — unique items folded into **WO5.0.0-025** (wrapper consolidation, GitLab exit-map, doctor watch-corpus/extras/version checks, riders); overlapping items were already covered by WO5.0.0-025 (action.yml format input, doctor truthfulness) and WO5.0.0-027 (cruft: post_pr_comment.py, coverage `_cli_commands` typo)
**Owner:** (unassigned — worktree `wo/4.0.0/cli-doctor-hygiene`)
**Priority:** P2 · Effort S-M · Risk L
**Scope:** `picosentry/cli_commands/{scan.py,sandbox.py,_common.py}`, `action.yml`, `ci-templates/gitlab-picosentry.yml`, `picosentry/_core/doctor.py`, `deploy/`, `pyproject.toml`, cruft files

**Gate:** `bash scripts/test.sh fast` + `uv run picosentry doctor` 13 checks green + `uv run picosentry check --help` identical to `python -m picosentry.scan check --help`.

## Objective
Close the small honesty/drift gaps the exploration round verified.

## Evidence (verified 2026-08-17)
1. Unified wrappers hand-duplicate inner argparse definitions (`check` cli_commands/scan.py:34-59 vs inner check.py:12-31; `cluster` cli_commands/sandbox.py:161-204) — the drift class that already bit once. `picosentry scan` shows the correct pattern (reuses inner `add_arguments`).
2. action.yml `format` input is dead — run step hardcodes `--format sarif`; `format: json` silently yields SARIF.
3. GitLab template treats only exit 2 as error — scan exits 3 (timeout)/4 (rule error)/5 (corpus age) pass silently with stale counts.
4. Doctor is scan+repo-centric: no watch rules-corpus check (`load_errors`), no optional-extras presence vs COMPONENT_STATUS (the pynacl-silent-degrade class), version-consistency omits `serve.config.version` + helm.
5. watch exit-2 collision (blocked-prompt vs argparse usage-error convention). serve.py:72-79 falsy-zero flags ignored. helm Chart.yaml URLs → stale PicoDome repo. `deploy/kubernetes` tag covered by WO4.0.0-009. GHA cache absent on push-tier docker jobs (bake hcl defines it; only release uses bake). 0-byte `_core/CLAUDE.md`; orphaned `scripts/post_pr_comment.py`; coverage omit `_cli_commands` → `cli_commands` typo.

## Deliverables
1. Wrapper consolidation via inner `add_arguments` reuse; action.yml format forwarded or removed; GitLab template exit-map fix; optional argcomplete.
2. Doctor: watch corpus check, extras-vs-claims check, version surfaces complete.
3. Riders: exit-code collision decision, helm URLs, docker cache, cruft sweep.
