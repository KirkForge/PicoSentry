# WO6.0.0-014 — Sandbox: cluster token lifecycle — grace=0 disables retirement, rotation lets stale-token holders self-refresh trust forever, EITHER-auth dead code

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/cluster-lifecycle`)
**Priority:** P0 · Effort M · Risk M
**Scope:** `picosentry/sandbox/cluster/{orchestrator.py,token_store.py}`, `picosentry/sandbox/daemon/{handler_routes_get.py,handler_routes_post.py}`, `tests/sandbox/test_cluster*.py`

**Gate:** `bash scripts/test.sh fast` + tests: grace=0 retires non-primary tokens immediately; a retired-lineage announcement is refused (ledger); API-token holders can actually fetch the cluster snapshot per the documented EITHER contract.

## Objective
Three cluster-trust defects found post-WO5-030.

## Evidence (verified 2026-08-18, explorer SA-AQ/AU; live repros)
1. **Grace env knob inverted** (MED, security): `orchestrator.py:449-454` `if grace > 0: retire_stale_tokens(grace)` — `PICODOME_CLUSTER_TOKEN_GRACE_SECONDS=0` (the fail-closed setting) disables retirement FOREVER instead of making it immediate; negatives parse through. Live: grace=0 → `would retire: False`.
2. **Self-refreshing trust** (MED): `apply_announcement` stamps adopted candidates `issued_at=announced_at` (`token_store.py:231`) — a value the ANNOUNCER chooses. A holder of any accepted token can iteratively self-rotate: each derived candidate gets a fresh grace clock and is itself a valid anchor → `retire_older_than` can never starve them; eviction-by-rotation fails while the evictee keeps gossiping. (ANY-MEMBER ceiling is documented; this corollary is not.)
3. **EITHER-auth dead code** (MED, truthfulness): `_authorize_cluster_route` (`handler_routes_get.py:68-86`) accepts API-token auth per its docstring — but both handlers unconditionally re-run `_check_cluster_token` inside (`:428`, post `:440`) → API tokens always 403 "cluster token required". Live repro confirms.
4. Small riders: `apply_announcement` TOCTOU (anchor decision under lock, promotion after release — concurrent `rotate()` clobber); `grace_expires` shipped but never validated by receivers; lock the promotion + clamp `issued_at` to `min(announced_at, now)` or delete the field.

## Deliverables
1. Unconditional retirement with `max(grace, 0)`; reject negative env values.
2. Retirement ledger (persist retired digests; refuse re-adoption of retired lineage) or monotonic `announced_at` per anchor — interim to quorum adoption.
3. Drop the redundant inner `_check_cluster_token` (outer gate already authorized) or thread an authorized-flag.
4. TOCTOU + grace_expires riders.
