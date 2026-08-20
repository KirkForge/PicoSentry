# WO7.0.0-017 — Sandbox: `TokenAuth` brute-force tracking dict not thread-safe

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/tokenauth-threadsafe`)
**Priority:** P1 · Effort S · Risk M
**Scope:** `picosentry/sandbox/auth.py`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + test: 8 threads × 200 concurrent failed-logins → no `RuntimeError: dictionary changed size during iteration`, no lost increments (final counter == 1600).

## Objective
`_failed_attempts` is a plain dict mutated under concurrent requests — lost increments and `RuntimeError` on iteration. Brute-force protection can be defeated by concurrent attempts.

## Evidence (verified 2026-08-20, explorer SA-sandbox; file:line chain)
- `auth.py:169-220`: `_failed_attempts` is read and written without a lock; the failure-counter increment and the window-reset path both mutate the dict.
- Concurrent attempts can lose increments (lockout never triggers) or raise `RuntimeError` mid-iteration.

## Deliverables
1. Add a `threading.Lock`; guard every read/write of `_failed_attempts`.
2. Regression test per the gate (concurrent stress, assert lockout triggers + no exception).