# WO5.0.0-004 — Sandbox: cluster gossip 401-dead on any auth-configured daemon

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/cluster-auth`)
**Priority:** P0 · Effort S-M · Risk M
**Scope:** `picosentry/sandbox/daemon/{handler_routes_get.py,handler_routes_post.py}`, `picosentry/sandbox/cluster/orchestrator.py`, `tests/sandbox/test_cluster*.py`

**Gate:** `bash scripts/test.sh fast` + new test: daemon with `PICODOME_API_TOKENS` + `PICODOME_CLUSTER_TOKEN` set → gossip GET (orchestrator's exact request) returns 200 and peers converge.

## Objective
Cluster convergence must survive API-token auth — the two features (WO-002 auth, WO-019 gossip) landed separately and break each other.

## Evidence (verified 2026-08-18, explorer SA-S; live repro)
`handler_routes_get.py:147-150`: GET `/api/v1/cluster/snapshot` requires `scan:read` API permission; `cluster/orchestrator.py:449-467` `_fetch_and_merge_peer` sends only `Accept` + `X-Cluster-Token` — never `Authorization`. Live: daemon with `PICODOME_API_TOKENS` + `PICODOME_CLUSTER_TOKEN`; the orchestrator's exact request → **401**. POST merge route same double-requirement (`handler_routes_post.py:113-116`) with no in-repo caller; docstring "Called by cluster peers" is wrong. No cluster test ever sets `PICODOME_API_TOKENS`.

## Deliverables
1. Cluster-token-authenticated gossip endpoints bypass API-token auth (they enforce their own token), or the orchestrator client sends an API token — pick one, document.
2. Fix the merge-endpoint docstring/callers.
3. Cluster convergence test with auth configured.
