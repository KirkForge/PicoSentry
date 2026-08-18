# WO6.0.0-021 — Core: truthfulness round 3 (maturity drift, scan-artifacts push tier, lockstep gaps, concurrency, runbooks)

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/core-truth-3`)
**Priority:** P1 · Effort M · Risk L
**Scope:** `picosentry/cli_commands/_maturity.py`, `.github/workflows/{ci.yml,admission-kind.yml}`, `action.yml`, `deploy/monitoring/picodome-alerts.yaml`, `picosentry/_core/doctor.py`, `tests/test_release.py`, `tests/test_doctor.py`

**Gate:** `bash scripts/test.sh fast` + tests: maturity badges pinned to COMPONENT_STATUS for overlapping names; uv.lock + manual.md version lockstep assertions; doctor pins prec/recall % claims to REPORT.json; dispatch cannot cancel a scheduled run (both workflows).

## Objective
The post-release audit found the truthfulness class persists on five more surfaces.

## Evidence (2026-08-18, explorer SA-AT; live-verified)
1. **`_COMMAND_MATURITY` contradicts every guarded surface** (`_maturity.py:23-26`): serve=STABLE there; Beta in experimental/README (test-enforced) + manual. Drift origin 2026-07-10, never reconciled. Also `emit_maturity_warning("cluster")` is a silent no-op ("cluster" missing from the dict — the promised Beta warning can never fire).
2. **scan-artifacts drift gate is PR-only** (`ci.yml:115-129`): routine direct-to-dev pushes (§1.5's documented flow) never check REPORT.json/BENCHMARKS.md sync — scanner changes with a forgotten regen are green while docs drift.
3. **action.yml `sarif-file` ignored for `format: github`** (`action.yml:50,69,91` vs `cli_service.py:436`): github format writes SARIF to `sarif.json`, not `--output`; with a custom `sarif-file` the declared output is a markdown file. Live-repro'd.
4. **uv.lock + manual.md are unguarded lockstep surfaces** (`uv.lock:1444`, `manual.md:3,76,2025`): the SARIF-incident class; no test parses either.
5. **Dispatch cancels scheduled runs, contradicting the documented invariant** (`ci.yml:21-23` — dispatch shares the `-nightly` group with `cancel-in-progress: true` for non-schedule events; the comment claims "never cancelled". Same in `admission-kind.yml:12-14` unconditional).
6. **All six alert runbook_url values are 404s** (`picodome-alerts.yaml:35,49,73,98,111,121` — wrong repo PicoDome, nonexistent `docs/runbooks/`; content lives in manual ch.13).
7. **Detection-metric claims unpinned** (experimental 100.00%/90.87% + README pair + manual): nothing compares the % claims to REPORT.json mean_* (WO5-028's recall move proves they drift). Doctor extension.
8. Riders: `security_check` docstring claims CI-lint use (none); `cli.py:55 _handle_health` test-only; landlock-real-exec never asserts "N ran, 0 skipped" (green-while-validating-nothing edge).

## Deliverables
Per item; every added gate must be provably able to fail (teeth tests, the WO5-025 pattern).
