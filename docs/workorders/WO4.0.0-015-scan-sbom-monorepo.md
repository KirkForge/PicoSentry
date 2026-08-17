# WO4.0.0-015 — Scan: SBOM fidelity + monorepo detection

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/4.0.0/sbom-monorepo`)
**Priority:** P1 · Effort S-M · Risk M (must not resurrect FPs on the negative corpus)
**Scope:** `picosentry/scan/{cli_service.py,sbom.py,engine.py,workspace.py}`, `tests/scan/`

**Gate:** `bash scripts/test.sh fast` + new tests: maven-component SBOM fires L2-MAVEN-ADV-001; CycloneDX 1.4/1.6 XML parse; nested-manifest fixtures (npm/pypi in subdir) fire their rule families; existing corpus numbers unchanged.

## Objective
SBOM-driven maven scans must not silently produce zero findings, and ecosystem detection must find manifests at any depth.

## Evidence (verified 2026-08-17)
1. `_prepare_sbom_target` writes `<dependency>` with groupId+version but NO `<artifactId>` (cli_service.py:380) → parse yields empty artifact → skipped by dep-confusion AND advisory — every maven component in a CycloneDX/SPDX SBOM unchecked.
2. CycloneDX XML namespace pinned to 1.5 (sbom.py:46,176) — 1.4/1.6 documents unparseable.
3. Ecosystem detection checks root manifests only (engine.py:239-250): monorepo with `packages/*/package.json` and no root manifest silently drops whole rule families; `_detected_pypi` checks `.venv` only while the rule layer handles `venv/` too; workspace discovery npm-only (workspace.py:82).

## Deliverables
1. artifactId from purl namespace / name split; CycloneDX 1.4/1.5/1.6 namespace support (keep 10MB cap + entity-expansion guard).
2. Bounded recursive manifest detection (reuse workspace SKIP_DIRS); pypi venv alignment; workspace discovery beyond package.json.
