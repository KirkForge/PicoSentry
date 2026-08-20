# WO7.0.0-031 — Scan: OSV disk-cache `_write_cache` is O(N²) — `_enforce_caps` glob+stat loop on every write

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/osv-disk-cache-on2`)
**Priority:** P2 · Effort S · Risk L
**Scope:** `picosentry/scan/intelligence.py`, `tests/scan/`

**Gate:** `bash scripts/test.sh fast` + test: 500 writes with 500 cached entries finish in <3s (was 9.24s first 500, 27.33s next 500); `_enforce_caps` not called every write.

## Objective
`_write_cache` calls `_enforce_caps` on every write, which globs + stats the entire cache dir. Cost grows O(N²) — measured 3× slowdown between 500 and 1000 entries.

## Evidence (verified 2026-08-20, explorer SA-scan; live measurement)
- `intelligence.py:121-130`: `_write_cache` calls `_enforce_caps` unconditionally.
- `intelligence.py:74-98`: `_enforce_caps` globs the cache dir and `os.stat`s every file.
- Measured: 500 writes = 9.24s; 500 more with 500 entries present = 27.33s (3×).

## Deliverables
1. Gate `_enforce_caps` with a write counter (run every N writes) or a size watermark; not every write.
2. Regression test per the gate (perf floor).