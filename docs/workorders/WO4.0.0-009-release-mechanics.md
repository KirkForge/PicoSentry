# WO4.0.0-009 — Release mechanics (next release ships correct)

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/4.0.0/release-mechanics`)
**Priority:** P0 (release imminent: dev ≈15 commits ahead) · Effort M · Risk L (keep release.yml diff minimal — verifiable at next tag)

**Scope:** `.github/workflows/{release.yml,verify-release.yml}`, `docker-bake.hcl`, `picosentry/experimental.py`, `deploy/kubernetes/deployment.yaml`, `deploy/helm/**`, `tests/test_release.py`, `CHANGELOG.md` head

**Gate:** `bash scripts/test.sh fast` + `uv run picosentry doctor` green + extended test_release covers every version-bearing surface (experimental notes, deploy manifests, bake default).

## Objective
The next release must ship correct docker tags, honest version strings, and anchored CHANGELOG sections.

## Evidence (verified 2026-08-17)
1. `release.yml:109` `--set '*.tags=...'` REPLACES the bake tag list → pushes only `picodome:v<TAG>`, dropping `:latest` and variants. README badge + docs point at `:latest`.
2. `experimental.py:111,116` hardcode `v2.1.1` (Docker tag + "PyPI v2.1.1 published"), mirrored into README — NOT covered by test_release drift guards. Next release ships a stale honesty table (the exact class the re-baseline round fought).
3. `deploy/kubernetes/deployment.yaml:35` pins `v2.0.16` — three releases stale, unguarded.
4. CHANGELOG has no `## [x.y.z]` anchors — nothing ties entries to releases.
5. verify-release/release `--version` runs never assert the output string — a missed bump passes.
6. `docker-bake.hcl:2` default TAG hardcoded (build script derives from pyproject; bake doesn't). 4 variant bake targets never built by any workflow — dead release config.
7. Version bump touches 5 files; doctor's version-consistency check omits `serve.config.version` + helm.

## Deliverables
1. release.yml pushes `${TAG}` AND `latest` (+ variant targets or delete them); bake default derives from pyproject.
2. experimental.py/README version strings derived from `__version__`; test_release extended to all version-bearing surfaces incl. deploy manifests.
3. verify-release asserts `--version` output == tag.
4. CHANGELOG `[x.y.z]` anchor convention (start with the next release).
