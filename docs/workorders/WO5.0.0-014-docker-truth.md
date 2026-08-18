# WO5.0.0-014 — Docker truth end-to-end: hub image, helm tag convention, existence gate

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/docker-truth`)
**Priority:** P0 (release-blocking honesty) · Effort M · Risk L
**Scope:** `deploy/helm/picodome/**`, `deploy/kubernetes/deployment.yaml`, `scripts/build_docker_multiarch.sh`, `.github/workflows/release.yml`, `tests/test_release.py`, `README.md`, `picosentry/experimental.py`, `docs/{manual.md,TECHNICAL_MANUAL.md,OFFLINE.md}`

**Gate:** `bash scripts/test.sh fast` + lockstep tests enforce ONE tag convention across helm/k8s/bake; release.yml gains a post-push `imagetools inspect` gate; `docker pull kirkforge/picodome:v2.1.2` (or current) works.

## Objective
The shipped claims about Docker images must be true, and the helm chart must be installable by default.

## Evidence (verified 2026-08-18, explorer SA-V; live registry query)
1. **v2.1.2 claim is false**: Hub tags are `['latest','v2.0.18','v2.0.17','v2.0.13']`; no v2.1.x. Yet `experimental.py:111,116`, `README.md:123,124,139`, `docs/manual.md:308`, `TECHNICAL_MANUAL.md:80,773` claim `kirkforge/picodome:v2.1.2`; `OFFLINE.md:51` air-gap instructions pull `:latest` = 3-releases-stale v2.0.18. `test_experimental_notes_version_lockstep` checks the version string only — nothing verifies registry existence. (Distinct from the known "push pending" state.md item: the defect is the false claim + missing gate.)
2. **Helm default tag can never resolve**: `Chart.yaml:6` `appVersion: "2.1.2"` (no `v`) + `deployment.yaml:42` `default .Chart.AppVersion` → `kirkforge/picodome:2.1.2`, but every registry tag and every release script uses `v`-prefix (`release.yml:121`, `build_docker_multiarch.sh:84`; raw k8s manifest pins `v2.1.2` and its guard enforces v-form while the helm guard enforces the un-prefixed form — `test_release.py:77-90` vs `:111-122`). `helm install` → `ImagePullBackOff` even after the push.
3. `scripts/build_docker_multiarch.sh:35 --ci` targets a nonexistent `picosentry-ci` build stage (documented as working in `docs/docker.md:28-29`).

## Deliverables
1. Push the current image (`TAG=v<x> docker buildx bake --push`).
2. Unify the v-prefix convention: `appVersion: "v2.1.2"` (or default `tag` in values), both lockstep tests enforce it, helm-template render test asserts the resolved tag exists.
3. Registry-existence gate in release.yml (`imagetools inspect` post-push); regenerate README/manual/TECHNICAL_MANUAL/OFFLINE claims; honesty table says "pending" until the gate passes.
4. Fix or remove the `--ci` flag.
