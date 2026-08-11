# WO2.0.0-009 — Reproducible Builds + Hash-Pinned Dependencies

**Series:** WO2.0.0 (improvement loop)
**Status:** OPEN
**Owner:** subagent (worktree `wo/2.0.0/reproducible-builds`)
**Gate:** `uv run ruff check picosentry/ tests/ scripts/` + `uv run mypy picosentry/` + `uv run pytest tests/ -m "not slow"`

## Objective
Close the own-supply-chain gaps (5/10): "No reproducible builds, no SLSA Level 3, no hash-pinned dependencies."

## Root cause being addressed
The release pipeline produces SBOM + SLSA + Sigstore, but builds are not reproducible (no `SOURCE_DATE_EPOCH`) and deps are not hash-pinned.

## Scope
- `pyproject.toml` / `uv.lock` — ensure the lockfile pins hashes (uv does this by default; verify)
- `Dockerfile` — set `SOURCE_DATE_EPOCH` for reproducible image builds; consider hash-pinned pip installs
- `.github/workflows/release.yml` — set `SOURCE_DATE_EPOCH` for the wheel/sdist build; verify `python -m build` is reproducible (build twice, compare hashes)
- Add a CI job that builds twice and asserts identical artifacts

## Done-condition
- Building the wheel/sdist twice yields identical hashes
- Docker image build is reproducible (or documented ceiling)
- A CI job asserts build reproducibility
- All gates green

## Notes
- Do NOT rewrite tests to pass.
- Preserve honest-doc annotations.
