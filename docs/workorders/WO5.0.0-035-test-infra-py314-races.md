# WO5.0.0-035 — Test-infra: py3.14 forkserver spawn race + slow-tier drift (new, flagged during P0 wave)

**Series:** WO5.0.0 (new 2026-08-18 — independently verified by 3 workers on pristine base b8e2ad67)
**Status:** DONE (2026-08-18, merge `2b166216`, agent SA-AG) — spawn budget 1s→30s (assertion unchanged; warm cost zero, cold forkserver covered; 3.14 CI legs green twice post-fix); L2-NSCOL added to the benchmark allowlist; slow-tier 180s timeouts measured + documented where they live (the fix is WO-028's DP cost, deliberately not blanket-raised); repo `.python-version` = 3.10 pins fresh-worktree uv resolution (was silently 3.14).
**Owner:** (unassigned — worktree `wo/5.0.0/test-infra-races`)
**Priority:** P2 · Effort S-M · Risk L
**Scope:** `tests/scan/test_cli_output_flags.py`, `tests/scan/test_benchmark.py`, `tests/scan/test_mutation_benchmark.py`, `tests/scan/test_validation.py`

**Gate:** `bash scripts/test.sh fast` green in a COLD fresh worktree on py3.14 (the repro condition) + slow-tier drift items fixed or re-tiered.

## Objective
The fast tier must be reproducibly green on cold checkouts and CI runners, not just warm dev trees.

## Evidence (verified 2026-08-18 by SA-Y, SA-Z, SA-AA — all on pristine base)
1. `tests/scan/test_cli_output_flags.py::TestQuietAndSummary::test_worker_operational_error_becomes_scan_error` fails deterministically in FRESH worktrees on py3.14 (forkserver is the default start method; worker spawn exceeds the test's 1-second `worker.join(timeout=1)` budget → ScanTimeout) while passing on the warm dev checkout. Fresh CI runners = cold → expect flaky/red push CI on 3.14 legs. Root cause is the spawn-latency budget, not the scan code.
2. Slow-tier drift (verified on base, outside fast): `test_benchmark::test_bench_rule_registration` — `L2-NSCOL` prefix missing from the valid-prefix allowlist (one-liner); `test_mutation_benchmark`/`test_validation` exceed their hardcoded 180s timeouts under typosquat `near_matches` load (related to WO5.0.0-028's DP cost).

## Deliverables
1. Spawn-budget fix: join timeout sized for cold forkserver spawn (or a worker-readiness signal instead of a fixed wall budget) — keeping the test's actual assertion (operational error → scan error mapping) intact.
2. NSCOL allowlist fix; slow-tier timeout review (document where the number lives; do not blanket-raise).
