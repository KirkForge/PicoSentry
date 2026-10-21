# WO9.0.0-103 — Deploy: `release.yml` cosign sign targets `:vv<TAG>` (double-v) → Docker image signing fails on every release

**Series:** WO9.0.0 (audit round 2026-08-23)
**Status:** **NOT A BUG — false positive** (re-verified 2026-10-21, see "Re-verification" below)
**Owner:** (unassigned)
**Priority:** P0 · Effort S · Risk M
**Scope:** `.github/workflows/release.yml`

**Gate:** `bash scripts/test.sh fast` + dry-run check: the cosign sign command in `release.yml` resolves to the same image tag that was pushed (`docker.io/kirkforge/picodome:v<TAG>`, single `v`).

## Objective
The `release.yml` docker job computes `TAG="v${GITHUB_REF_NAME#v}"` (line 125), which strips the leading `v` from the git tag then re-adds it, yielding `TAG=v2.2.0`. The image is built and pushed as `:v2.2.0` (bake uses `${TAG}`, lines 131-142 correct). But the cosign sign step (line 157) uses `cosign sign --yes "docker.io/kirkforge/picodome:v${TAG}"` — prepending a SECOND `v` to a `TAG` that already starts with `v`, producing `docker.io/kirkforge/picodome:vv2.2.0`. That tag does not exist on the registry, so cosign signing fails. Every release that enables `DOCKER_PUSH_ENABLED=true` fails at the signing step (after the image is already published), blocking the release and leaving an unsigned image.

## Evidence (verified 2026-08-23, explorer; live shell repro)
- `release.yml:125`: `TAG="v${GITHUB_REF_NAME#v}"` → for `GITHUB_REF_NAME=v2.2.0`, `TAG=v2.2.0`.
- `release.yml:131`: `TAG="${TAG}" docker buildx bake --push` → image pushed as `:v2.2.0` ✓ (correct).
- `release.yml:132`: `docker buildx imagetools inspect "docker.io/kirkforge/picodome:${TAG}"` → `:v2.2.0` ✓ (correct).
- `release.yml:142`: `docker buildx imagetools inspect "docker.io/kirkforge/picodome:${TAG}"` → `:v2.2.0` ✓ (correct).
- `release.yml:157`: `cosign sign --yes "docker.io/kirkforge/picodome:v${TAG}"` → `:vv2.2.0` ✗ (DOUBLE `v` — tag does not exist).
- `release.yml:162`: `docker run --rm "docker.io/kirkforge/picodome:${TAG}"` → `:v2.2.0` ✓ (correct).
- Live shell repro (`/tmp/opencode/test_release_tag.sh`):
  ```
  GITHUB_REF_NAME="v2.2.0"
  TAG="v${GITHUB_REF_NAME#v}"
  echo "TAG=$TAG"                       # TAG=v2.2.0
  echo "cosign target: ...picodome:v${TAG}"   # ...picodome:vv2.2.0   <-- BUG
  echo "inspect target: ...picodome:${TAG}"  # ...picodome:v2.2.0    <-- correct
  ```
  Only line 157 has the double-`v`; all other `${TAG}` references are correct.

## Re-verification (2026-10-21) — the premise is wrong; no code change needed

The original repro computed the cosign target from line 125's `TAG` (`v2.2.0`). But the
cosign step is its own `run:` block and **recomputes `TAG` on its own line 156** as
`TAG="${GITHUB_REF_NAME#v}"` — WITHOUT the `v` prefix. Its `v${TAG}` is therefore
`v` + `2.2.0` = `v2.2.0`, identical to the bake/inspect/`docker run` targets.

Every image reference in the docker job, evaluated as bash would in its own step:

| step | line | TAG assignment | target |
|------|------|----------------|--------|
| build & push | 125 | `TAG="v${GITHUB_REF_NAME#v}"` | bake pushes `:v2.2.0` |
| exists gate | 137 | `TAG="v${GITHUB_REF_NAME#v}"` | `imagetools inspect :v2.2.0` |
| cosign | 156 | `TAG="${GITHUB_REF_NAME#v}"` | `cosign sign :v2.2.0` |
| verify | 161 | `TAG="v${GITHUB_REF_NAME#v}"` | `docker run :v2.2.0` |

Checked across tag forms — all MATCH:

```
v2.2.0           bake=...:v2.2.0        cosign=...:v2.2.0        MATCH
2.2.0            bake=...:v2.2.0        cosign=...:v2.2.0        MATCH
v2.2.0-rc1       bake=...:v2.2.0-rc1    cosign=...:v2.2.0-rc1    MATCH
release-2.2.0    bake=...:vrelease-2.2.0 cosign=...:vrelease-2.2.0 MATCH
```

The two spellings are deliberate, not a bug: the `v`-prefixed `TAG` feeds the
`docker-bake.hcl` tag list (`:v<TAG>, :latest`), and the bare `TAG` feeds the cosign
call, which supplies its own `v`. **No change is warranted** — applying the original
WO's proposed edit (line 157 → `:${TAG}`) would BREAK signing, because it would sign
`2.2.0`, a tag that does not exist.

`release.yml` parses as valid YAML, and all four references resolve identically.

## Deliverables
No code change — the WO is closed as a false positive.

Follow-up (readability, not correctness): the asymmetry between line 156
(`TAG="${GITHUB_REF_NAME#v}"`) and lines 125/137/161 (`TAG="v${GITHUB_REF_NAME#v}"`)
is easy to misread, and it already cost one audit round. A comment in the cosign step
saying why its `TAG` is bare (it supplies the `v` itself) prevents the next reader or
auditor from re-raising this false positive — and from "fixing" it into a broken state.
