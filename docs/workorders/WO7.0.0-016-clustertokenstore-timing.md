# WO7.0.0-016 — Sandbox: `ClusterTokenStore.is_accepted` uses non-constant-time dict membership

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/cluster-token-ctcompare`)
**Priority:** P1 · Effort S · Risk M
**Scope:** `picosentry/sandbox/cluster/token_store.py`, `picosentry/sandbox/daemon/handler_routes_get.py`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + test: `is_accepted` compares with `hmac.compare_digest` for each candidate; timing test asserts no early-exit ordering difference vs. a fixed-time baseline (or unit-test the constant-time path directly).

## Objective
`return token in self._accepted` is a non-constant-time dict membership check — timing side-channel on cluster token validation. Violates the AGENTS.md permanent convention (hmac.compare_digest for any secret/token comparison).

## Evidence (verified 2026-08-20, explorer SA-sandbox; file:line chain)
- `token_store.py:121-123`: `def is_accepted(self, token): return token in self._accepted`.
- `handler_routes_get.py:35`: called from the cluster handshake path.

## Deliverables
1. Iterate the accepted set and `hmac.compare_digest` each candidate (short-circuit only on match); or move the comparison to a constant-time structure.
2. Regression test per the gate.