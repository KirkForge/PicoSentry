# WO7.0.0-009 — Firewall: `UNRESOLVED` verdict cached with full TTL (stale 502 on newly-published versions)

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/firewall-unresolved-cached`)
**Priority:** P1 · Effort S · Risk M
**Scope:** `picosentry/firewall/scanner.py`, `tests/firewall/`

**Gate:** `bash scripts/test.sh fast` + test: a package that returned `UNRESOLVED` at T0 and is published at T1 (cache advanced past short TTL) is re-resolved and allowed; the full-TTL path is gone.

## Objective
`UNRESOLVED` is cached for 3600s. A version published during that window is blocked for up to an hour — a stale 502 on a fresh publish.

## Evidence (verified 2026-08-20, explorers SA-scan AND SA-seam — deduped; file:line chain)
- `scanner.py:141-152`: the verdict cache stores `UNRESOLVED` with the same TTL as `ALLOW`/`DENY` (3600s).
- No negative-cache differentiation; no short-TTL branch for `UNRESOLVED`.

## Deliverables
1. Don't cache `UNRESOLVED` (re-resolve every time) OR use a short TTL (e.g. 15-30s) for the `UNRESOLVED` case.
2. Regression test per the gate.