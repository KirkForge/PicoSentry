# WO7.0.0-032 — Scan: `_is_package_reachable` rescans entire source tree per package (O(packages × files))

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/is-package-reachable`)
**Priority:** P2 · Effort M · Risk L
**Scope:** `picosentry/scan/rules/advisory_check.py`, `tests/scan/`

**Gate:** `bash scripts/test.sh fast` + test: 100 packages on a 50-file source tree complete in <0.5s (was 2.043s); a single import-map is built per scan.

## Objective
`_is_package_reachable` walks the whole source tree once PER package — O(packages × files). Reachability checks dominate advisory-check wall time at scale.

## Evidence (verified 2026-08-20, explorer SA-scan; live measurement)
- `advisory_check.py:316-344`: for each package, the function iterates the source tree looking for imports.
- Measured: 100 packages × 50 files = 2.043s; cost scales with the product.

## Deliverables
1. Build ONE import-map per scan (set of imported module roots), then check each package against the map (O(packages + files)).
2. Regression test per the gate (perf floor).