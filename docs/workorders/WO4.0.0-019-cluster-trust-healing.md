# WO4.0.0-019 — Sandbox: cluster trust + partition healing

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** PARTIAL 2026-08-17 (worktree `wo/4.0.0/sandbox-p1`). Landed: digest-only gossip snapshots (no secret material; legacy raw snapshots still mergeable for rolling upgrades), slow-cadence OFFLINE-peer re-probe + heal via merge, scheduled retire_stale_tokens (PICODOME_CLUSTER_TOKEN_GRACE_SECONDS, default 3600/0=off), scheduled retention run_cleanup (PICODOME_RETENTION_INTERVAL_SECONDS, default daily/0=off), JSONL runtime max_jobs cap, SQLite queries inside the lock, Redis zset prune. NOT landed: HMAC-with-primary rotation announcements (rotation via gossip deliberately disabled — digest snapshots cannot carry new token material; rotate = config distribution until announcements exist), check_hostname=False ceiling, JSONL append-only compaction between rewrites. Evidence: tests/sandbox/test_cluster_trust_healing.py, updated test_cluster.py / test_cluster_3node.py protocol contracts.
**Owner:** (unassigned — worktree `wo/4.0.0/cluster-trust`)
**Priority:** P2 · Effort M · Risk M (protocol change; cluster is BETA)
**Scope:** `picosentry/sandbox/cluster/{orchestrator.py,state.py,token_store.py}`, `tests/sandbox/test_cluster*.py`

**Gate:** `bash scripts/test.sh fast` + 3-node partition/heal test (extend test_cluster_3node) + snapshot contains no secret material (test).

## Objective
Gossip that doesn't distribute secrets, and partitions that heal.

## Evidence (verified 2026-08-17)
1. GET /cluster/snapshot ships the raw token_store (primary + accepted rotation tokens) + legacy cluster_token (state.py:194-200, token_store.py:124-142) — any holder of one stale-but-accepted token can fetch the primary forever; the adopt-loop lets any member inject accepted tokens cluster-wide (state.py:227-234); `check_hostname=False` (orchestrator.py:452, documented ceiling). Rotation grace period = full compromise window.
2. `_gossip_loop` contacts ONLINE peers only (orchestrator.py:407) — after a transient partition both nodes mark each other OFFLINE and neither ever probes again; with SQLite persistence the split-brain survives restarts; `handle_heartbeat` ignores unknown node_ids so returning nodes can't rejoin.
3. Stores: JSONL never compacted at runtime (full rewrite per update); Redis `_max_jobs` dead (no TTL/prune); retention `run_cleanup` CLI-only, never scheduled.

## Deliverables
1. Snapshots carry token IDs/versions, not secrets (rotation via HMAC-with-primary announcement); adoption policy decision.
2. Slow-cadence OFFLINE-peer re-probe + rejoin path; auto-schedule `retire_stale_tokens` + retention cleanup.
3. JSONL runtime cap + compaction; Redis prune; SQLite queries inside the lock.
