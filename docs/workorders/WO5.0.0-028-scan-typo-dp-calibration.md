# WO5.0.0-028 — Scan: typosquat DP acceleration + short-name calibration (folds WO4.0.0-014 remainder)

**Series:** WO5.0.0 (fold 2026-08-18 from WO4.0.0-014 PARTIAL + state.md carries)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/typo-dp`)
**Priority:** P1 · Effort M · Risk M (determinism + recall must hold)
**Scope:** `picosentry/scan/rules/{corpus_index.py,_typosquat_corpus/**}`, `picosentry/scan/rules/__init__.py` (L2-TYPO-001 config), `tests/scan/`

**Gate:** `bash scripts/test.sh fast` + benchmark: L2-TYPO-001 DP cost < 1s on the 3.9k-file tree with findings byte-identical; short-name calibration shifts precision/recall only in the documented direction (re-baseline card if the numbers move).

## Objective
Close the last scan-perf gap (typo DP ≈4.5s pure-Python) and the L2-TYPO-001 short-name calibration flagged by WO4.0.0-022.

## Evidence (carried, verified 2026-08-17)
1. WO4.0.0-014 landed 1.33× CPU overall but the ≥2× gate was NOT met: `L2-TYPO-001` remains ≈4.5s of pure-Python banded DP per scan (corpus_index.py — halo-banded exact trie already landed). Needs a C accelerator or SymSpell-style precomputed index; deliberately deferred as new risk surface.
2. L2-TYPO-001 short-name calibration (carried from WO4.0.0-022): short package names produce FP-heavy near-match scoring; calibration was flagged, never done.
3. L2-LOCK-001 fires scan-side but the firewall excludes it (carried from state.md) — decide: calibrate for both surfaces or document the split honestly.

## Deliverables
1. DP acceleration (SymSpell-style index or C accelerator via stdlib-adjacent means only — no new deps without owner OK); findings byte-identical on the benchmark tree.
2. Short-name calibration for L2-TYPO-001; re-baseline the model card if metrics move.
3. L2-LOCK-001 surface decision (calibrate or document).
