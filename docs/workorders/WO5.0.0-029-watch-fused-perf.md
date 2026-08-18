# WO5.0.0-029 — Watch: fused-pass <1s/MB + perf-ceiling test robustness (folds WO4.0.0-016 remainder)

**Series:** WO5.0.0 (fold 2026-08-18 from WO4.0.0-016 PARTIAL + P0-wave worker flags)
**Status:** PARTIAL (2026-08-18, merge `c78f3194`, worker SA-AK) — 2.8-2.9x landed via equivalence-preserving fusion (C-level textlike gate, rot13-gate fan-out, whole-text spaced-collapse, branch-conjunction prefilter + per-evaluate memo); benign 200KB 1.9s -> 0.64s CPU, b64-heavy 0.93 -> 0.36s. Byte-identical verdicts vs 5652-case golden differential; corpus hash unchanged; determinism green. <1s/MB NOT met on benign under load (~3.2 s/MB loaded / ~1.6 idle-equiv; residual = 2x normalize + morse regex + classifier fan-out, `ceiling:`-annotated at check()). Both perf ceilings CPU-time + load-verified. Remaining fused-pass work deferred — the target needs the normalize pipeline itself redesigned.
**Owner:** (unassigned — worktree `wo/5.0.0/watch-fused`)
**Priority:** P2 · Effort M-L · Risk M (corpus floors + determinism must hold; WO5.0.0-011's recursive decode adds work here)
**Scope:** `picosentry/watch/prompt_guard/{__init__.py,normalize.py,classifier.py}`, `tests/watch/test_watch_perf_metrics.py`

**Gate:** `bash scripts/test.sh fast` + measured <1s/MB on the WO4.0.0-007 corpus (unloaded machine, `time.monotonic`, medians) + corpus floors + `--verify-determinism` green + perf-ceiling test passes under CI load.

## Objective
Close the watch perf remainder (2.8× landed, 8.8s/MB → target <1s/MB) and make the perf-ceiling test load-robust instead of machine-condition-dependent.

## Evidence (carried + new)
1. WO4.0.0-016 landed 4.88s→1.75s per 200KB (2.8×); the remaining floor is ~2× normalize (~0.45s) + decode-rescan (~0.3s) + classifier (~0.35s) + ~10 full regexes — needs normalize+classifier restructured into single fused passes (not attempted: corpus-floor risk). Note WO5.0.0-011 added recursive decode (depth ≤2, budgeted) — re-measure with it in place.
2. NEW (flagged by 3 workers during the 2026-08-18 P0 wave): `tests/watch/test_watch_perf_metrics.py::TestScanCostCeiling::test_200kb_benign_prompt_under_ceiling` fails under machine load (measured 4.86–8.1s vs the 4.0s ceiling with load 25–34 from parallel runs; passes unloaded). The ceiling is a wall-clock constant — recalibrate against CPU-time or a load-normalized budget so CI parallellism can't flip it. (Legitimate recalibration: measurement conditions changed, population did not — document where the number lives.)

## Deliverables
1. Fused single-pass normalize+classify (corpus hash unchanged or re-baselined honestly; floors green).
2. Perf-ceiling test robust to load (CPU-time budget or load-scaled ceiling), with the recalibration documented.
