# WO2.0.0-001 — Supply-Chain Security Hardening

**Series:** WO2.0.0 (improvement loop)
**Status:** OPEN
**Owner:** subagent (worktree `wo/2.0.0/supply-chain`)
**Gate:** `uv run pytest tests/ -m "not slow"` + `uv run ruff check` + `uv run mypy picosentry/`

## Objective
Harden the supply-chain security posture of PicoSentry itself and of the packages it scans.

## Scope
- Verify the dependency-audit CI job covers the full lockfile tree (already done — confirm it stays green).
- Confirm the release pipeline produces SBOM + SLSA provenance + Sigstore signatures (release.yml) and that verify-release.yml exercises them.
- Audit the scanner's own rule catalog for coverage gaps against current known supply-chain attack patterns.
- Confirm `pip-audit` / `uv export` audit path is correct and not silently skipping packages.

## Root cause being addressed
Supply-chain security is the product's core value; the CI/release evidence chain must be complete and verified, not aspirational.

## Done-condition
- dependency-audit job green on the full 116-pkg tree.
- release.yml + verify-release.yml evidence chain is coherent (SBOM, SLSA, Sigstore).
- No new vulnerabilities in `uv export` audit.

## Notes
- Do NOT touch tests to make them pass. Fix root causes.
- Do NOT commit `picowatch_audit.db`, `*.corpus.json`, `.coverage`.
