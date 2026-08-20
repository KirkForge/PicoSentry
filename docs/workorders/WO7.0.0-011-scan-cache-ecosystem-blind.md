# WO7.0.0-011 — Scan: cache blind to ecosystem detection (empty `.venv`/`.tox` → stale no-pypi verdict)

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/scan-cache-ecosystem`)
**Priority:** P1 · Effort M · Risk L
**Scope:** `picosentry/scan/cli_service.py`, `picosentry/scan/engine.py`, `tests/scan/`

**Gate:** `bash scripts/test.sh fast` + test: scan with empty `.venv` (cache miss) then scan with `.venv` populated → second scan re-detects pypi and fires pypi rules; cache key differs between the two.

## Objective
Empty ecosystem marker dirs (`.venv`, `.tox`) flip ecosystem detection but the detection result is not part of the cache key. First scan with empty `.venv` → `input_hash=""`, cache returns stale no-pypi-rules verdict after the env is populated.

## Evidence (verified 2026-08-20, explorer SA-scan; file:line chain)
- `cli_service.py:165-241`: ecosystem detection runs but its result is not folded into the cache key.
- `engine.py:114-168`: `input_hash` is computed from file contents only; the detected-ecosystem set is not part of the hash.
- Empty `.venv` → pypi detected but `input_hash=""`; populated `.venv` later still hits the empty-hash cache row.

## Deliverables
1. Include the detected ecosystem set (sorted tuple) in the cache key.
2. Regression test per the gate.