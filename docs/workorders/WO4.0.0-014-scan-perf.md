# WO4.0.0-014 — Scan: throughput + daemon responsiveness

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/4.0.0/scan-perf`)
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
