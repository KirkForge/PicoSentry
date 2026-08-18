# WO5.0.0-028 — Scan: typosquat DP acceleration + short-name calibration (folds WO4.0.0-014 remainder)

**Series:** WO5.0.0 (fold 2026-08-18 from WO4.0.0-014 PARTIAL + state.md carries)
**Status:** DONE (2026-08-18, merge `61d41f2b`, worker SA-AJ) — SymSpell delete-2 index for the no-keyboard dist<=2 path (exact by construction; keyboard path keeps the trie): DP 9.7s -> 0.15-0.21s (46-65x) on the 4.3k tree, incremental build + scan-start prewarm outside the timebox; findings byte-identical (6217-call replay 0 mismatches; full-validation cmp-identical; sha256-identical tree findings). NEW BUG fixed en route: dev silently DROPPED L2-TYPO-001 findings via the 5s rule timebox on dep-heavy trees (regression test test_typosquat_timebox.py). Short-name calibration: KNOWN_LEGITIMATE += {pkg,uid,num} + negative fixture (precision/recall unmoved: 1.0000/0.9087; floors intact). L2-LOCK-001: keep split as-is (lockfile rule structurally FP on registry metadata; exclusion comment already honest). Card regenerated (population +1 neg only). Slow tier: validation run 343s -> 190s (DP fixed; remaining 155s is other rules — next owner). Item 5 PARTIAL by scope.
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
