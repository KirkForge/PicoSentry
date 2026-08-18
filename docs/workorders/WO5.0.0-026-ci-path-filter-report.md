# WO5.0.0-026 — CI: path-filter completion + REPORT.json gating + nightly cancellation

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/ci-paths`)
**Priority:** P2 · Effort S · Risk L
**Scope:** `.github/workflows/ci.yml`, `tests/test_ci_paths.py`

**Gate:** `bash scripts/test.sh fast` + extended `tests/test_ci_paths.py` pins classifying the five residual paths as code; scan-artifacts diffs `tests/scan/fixtures/validation/REPORT.json` too.

## Objective
Close the WO-017 path-filter remainder: no file that shapes builds, gates, or guarded artifacts may classify as docs-only.

## Evidence (verified 2026-08-18, explorer SA-V; live regex evaluation)
1. **Residual holes**: `docs/BENCHMARKS.md`, `.dockerignore`, `ci-templates/gitlab-picosentry.yml`, `.env.example`, `.pre-commit-config.yaml` all classify docs-only against `ci.yml:58-59` regexes → every pytest/type-check/scan-artifacts job skips. Sharpest: a hand-edit PR to `docs/BENCHMARKS.md` — the exact file `scan-artifacts` guards via `git diff --exit-code` (`ci.yml:120`) — never runs its own sync gate. `.dockerignore` shapes the build context (missed by the same sweep that added `Dockerfile[^/]*$`). `tests/test_ci_paths.py` pins the current holey classification — extend the pins with the fix.
2. **scan-artifacts regenerates REPORT.json but never gates it** (`ci.yml:116-120`): diffs only `docs/BENCHMARKS.md`; REPORT-only fields (`total_fixtures`, `total_positive`, `total_negative`) can drift with the job green; zero tests pin the committed REPORT.json.
3. **Nightly cancellable by a main push**: concurrency group `ci-…-${{ github.ref }}` (`ci.yml:17-19`) is `refs/heads/main` for both schedule and main pushes with `cancel-in-progress: true` — a push during the 03:00 nightly kills the exhaustive run.
4. Related staleness: `picosentry-scan.yml:16` `checkout@v4` vs `@v7` everywhere else.

## Deliverables
1. Add the five paths to code_re/scan_re; extend test pins.
2. `git diff --exit-code docs/BENCHMARKS.md tests/scan/fixtures/validation/REPORT.json`.
3. Separate concurrency group for scheduled runs (or cancel-in-progress: false for nightly).
4. Note for the future: PR tier triggers only on `branches: [main]` while the documented flow is direct pushes to dev — the fast tier may be local-only in practice (verify PR history; adjust triggers).
