# WO4.0.0-014 — Scan: throughput + daemon responsiveness

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** CLOSED-FOLDED (2026-08-18) — remainder (L2-TYPO-001 ≈4.5s pure-Python DP, needs C accelerator or SymSpell-style index) moved to **WO5.0.0-028** together with the L2-TYPO-001 short-name calibration + L2-LOCK-001 surface decision. Landed & shipped in v2.1.2: daemon responsiveness + caches with tests; throughput 1.33× CPU measured (scan 18.1→13.6s CPU, zero rule timeouts, engine rebuild 0.26→0.011s, count_relevant_files 0.55→~0.02s); halo-banded exact trie (corpus_index.py, brute-force-equivalence test), shared stat-keyed byte-read cache, single-walk iter_source_files; findings byte-identical. The ≥2× gate was NOT met — rule parallelism measured NEGATIVE under the GIL (30.8s vs 17.1s wall, interleaved A/B), rules stay sequential (documented in engine.py).
**Owner:** worktree `wo/4.0.0/scan-watch-p1`
**Priority:** P1 · Effort L · Risk H (determinism + timebox regressions)
**Scope:** `picosentry/scan/{engine.py,campaigns/_base.py,advisory_check.py,daemon/__init__.py,daemon/handler.py}`, `tests/scan/`

**Gate:** `tests/scan/test_deterministic_output.py` + `test_engine_timebox.py` green; benchmark ≥2× on a synthetic 3.9k-file tree; scan-daemon /health responds during /scan (new test); `bash scripts/test.sh fast`.

## Objective
Cut scan wall time (measured 8.9s on 3.9k files) and make the scan daemon responsive during scans.

## Evidence (measured 2026-08-17)
1. Rules execute strictly sequentially despite the pool (engine.py:386-414: submit + immediate `result(timeout=)`) — max_workers=32 never used concurrently; full scan = sum of all rules. The 4 campaigns at 1.3-1.5s each = 5.6s of 8.9s, each running its own full `rglob("*")`+read pass (campaigns/_base.py:159,205,300-332).
2. Corpus re-hashed on every `ScanEngine()` (engine.py:137-153) — 3× per cached CLI run + per workspace project + per daemon request; `count_relevant_files` walks node_modules (helpers:6 lacks it in _SKIP_DIRS); package-intel rglob per scan; `_is_package_reachable` re-rglobs per advisory package.
3. Scan daemon single-threaded (`HTTPServer`, daemon/__init__.py:95) — one /scan blocks /health (k8s kills it); per-request engine rebuild re-hashes corpus (~0.55s) while `_engine_cache` sits unused by /scan.

## Deliverables
1. Parallel rule execution preserving per-rule timebox + determinism (ordered fan-in, stable finding order).
2. One shared file-content pass for campaigns + pattern rules; per-process corpus-hash cache; node_modules in _SKIP_DIRS; reachability list computed once per scan.
3. Scan daemon: ThreadingHTTPServer, reuse `_engine_cache` in /scan.
