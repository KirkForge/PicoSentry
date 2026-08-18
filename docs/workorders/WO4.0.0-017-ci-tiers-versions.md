# WO4.0.0-017 — CI: path-filter hole, tier placement, version matrices

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** DONE (PARTIAL 2026-08-17 → complete 2026-08-18: the 3.14 classifier landed with the matrix extension; path-classification pins extended by WO5.0.0-026 incl. the residual holes it left). D1+D2 done (incl. the live postgres dbname bug), D3 CI matrix done, path classification pinned by tests/test_ci_paths.py
**Owner:** (unassigned — worktree `wo/4.0.0/ci-tiers`)
**Priority:** P1 · Effort M · Risk M (workflow edits; keep concurrency cancellation)
**Scope:** `.github/workflows/{ci.yml,admission-kind.yml}`, `scripts/test.sh`

**Gate:** docs-only PR simulation shows expected skips; push CI green; `bash scripts/test.sh integration` locally; `python3 -c yaml.safe_load` OK.

## Objective
Close the path-filter hole, fix tier placement, refresh stale version matrices, and dedupe nightly.

## Evidence (verified 2026-08-17)
1. **Path-filter hole**: `code_re` (ci.yml:53) misses `scripts/**`, `Dockerfile`, `docker-bake.hcl`, `action.yml`, `deploy/**` — a PR breaking `scripts/test.sh` or the Dockerfile skips test-fast/type-check/cli/determinism (lint only); Dockerfile breakage surfaces only post-merge.
2. admission-kind.yml builds 3 kind clusters on EVERY push with stale matrix (v1.28/1.29/1.30 — 1.28 EOL Oct 2024); postgres matrix 15/16 (17/18 current).
3. `integration` profile ≈ fast in content (differs only by malicious_workload marker that skips without the nightly env, + timeout) — the 4-python push matrix adds zero coverage; either include network-marker tests on push or rename.
4. nightly-coverage re-runs the full suite on top of nightly-tests — two full runs where one `nightly --cov` would do.
5. BENCHMARKS.md sync gate is `continue-on-error: true` (ci.yml:110-111) — the doc-honesty drift check fails silently right after the re-baseline made it meaningful.
6. Python 3.14 absent from classifiers + CI matrix (3.14 GA Oct 2025; locked deps all support it).
7. determinism-check is tautological (asserts `_core` enums identical to their re-exports; the real variant — watch's PASS/WARN/BLOCK Verdict — uncovered).

## Deliverables
1. Add the missing paths to `code_re`; graduate BENCHMARKS-sync to enforcing.
2. admission-kind → nightly, current k8s minors; postgres +17/18; merge nightly coverage into nightly-tests; decide integration-profile content.
3. py3.14 in matrix + classifiers (or documented ceiling).

## Resolution (2026-08-17, wo/4.0.0/release-mechanics)
1. **DONE** — `code_re` now covers `scripts/`, `deploy/`, `Dockerfile*`, `docker-bake.hcl`, `action.yml` (plus the pre-existing trees). New `tests/test_ci_paths.py` pins the classification (docs-only → skip, scripts/Dockerfile/deploy → run) so the hole can't silently reopen. BENCHMARKS-sync step and the REPORT.json regen step above it both lost `continue-on-error` — a soft-failing regen made the enforced diff check vacuous, so both were hardened (the already-hard determinism step runs the same machinery, so this adds no new failure mode).
2. **DONE** — admission-kind.yml: push trigger removed, runs nightly (cron 05:00, offset from ci.yml's 03:00) + manual dispatch; k8s matrix v1.28–v1.30 → v1.34.8/v1.35.5/v1.36.1 (all verified present on Docker Hub); kind v0.23.0 → v0.32.0, kind-action v1.10.0 → v1.14.0 (current latest). Postgres matrix 15/16 → 15/16/17/18. nightly-coverage job deleted; nightly-tests runs the nightly profile with `--cov` in one pass and uploads coverage.xml with the junit report. Integration-profile content decided: `scripts/test.sh integration` now exports `PICODOME_SANDBOX_TESTS=1`, so the push matrix actually runs the malicious_workload tier fast skips (~21s per leg, slowest single test 5.1s — measured) instead of duplicating fast's content. The `network` marker stays excluded (no tests currently carry it).
3. **PARTIAL (out of file scope)** — '3.14' added to the push `test-matrix`. The `pyproject.toml` classifiers entry is not in this worktree's file scope; one-line change for the pyproject owner: add `"Programming Language :: Python :: 3.14"` to `project.classifiers`.

**Also fixed here (context handoff, failed runs 32043226257 / 31746260038):** postgres-live-test built per-file DB URLs by appending `"/$db"` to a URL that already ended in a database name — psycopg2 took everything after the last slash as the dbname and received the invalid `picoshogun/pg_live_...`. The pytest invocation now builds `postgresql://user:pass@host:port/$db` from parts; per-file database isolation (fresh CREATE DATABASE per test file) is preserved. **Evidence #7** also closed: determinism-check now pins watch's PASS/WARN/BLOCK Verdict vocabulary (`picosentry.watch.types`), which the old `_core` re-export assertions never touched.
