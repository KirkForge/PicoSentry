# WO4.0.0-009 — Release mechanics (next release ships correct)

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** DONE (PARTIAL 2026-08-17 → complete 2026-08-18: D2/D4 — docker tag clobbering, tag-convention lockstep, deploy drift guards, registry-existence gate — landed as WO5.0.0-014; the only remainder, the v2.1.2 image PUSH itself, is tracked as the WO5.0.0-014 PARTIAL, tooling-blocked). D1+D3 done 2026-08-17: sdist normalizer shipped (`scripts/normalize_sdist.py`, wired into release.yml + push-tier CI, unit-tested)
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

## Resolution (2026-08-17, wo/4.0.0/release-mechanics)
1. **DONE** — release.yml now overrides the bake `TAG` *variable* (`TAG=v<x> docker buildx bake --push`) instead of `--set '*.tags='` (which replaced the tag list and dropped `:latest`). The 4 never-built variant bake targets (`*-ci/scanner/sandbox/server`) were deleted per the deliverable's delete option; their Dockerfile stages remain for local builds. Bake default changed from hardcoded `v2.1.2` to `"dev"` — the WO's "derives from pyproject" intent is met by removing the stale-able version entirely: release.yml injects the git tag, `scripts/build_docker_multiarch.sh` already derives from pyproject, and a literal version in the .hcl no longer exists to go stale.
2. **PARTIAL (out of file scope)** — deriving the strings inside `picosentry/experimental.py` from `__version__` requires editing `picosentry/**`, owned by another agent in this round; deferred. Mitigation landed instead: `tests/test_release.py` now drift-guards every version-bearing surface — experimental.py notes (Docker tag + PyPI string), README pull line, `deploy/kubernetes/deployment.yaml` image (bumped v2.0.16 → v2.1.2), plus the existing helm/subpackage guards. A missed bump now fails fast, so the manual lockstep bump cannot silently ship stale strings.
3. **DONE** — verify-release.yml and release.yml both assert the first `--version` line equals `PicoSentry (unified) v<TAG>` (format verified against the live CLI).
4. **OUT OF SCOPE (orchestrator)** — CHANGELOG.md is a shared/orchestrator-only file; the `[x.y.z]` anchor convention must land with a CHANGELOG edit. Not done from this worktree.

**Also shipped here (context handoff):** `scripts/normalize_sdist.py` — sdist post-build normalizer (setuptools ignores SOURCE_DATE_EPOCH for tar dir-entry mtimes/uids and the gzip header). Wired into release.yml (normalized artifact is what gets checksummed/signed/uploaded) and the push-tier `reproducible-build` job (two sdist builds, both normalized, hashes must match). Unit-tested in `tests/test_release.py` with tiny fixture tarballs — two differently-stamped builds normalize to identical bytes.
