# WO4.0.0-017 — CI: path-filter hole, tier placement, version matrices

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** OPEN
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
