# WO5.0.0-030 — Sandbox: cluster token rotation announcements + trust ceilings (folds WO4.0.0-019 remainder)

**Series:** WO5.0.0 (fold 2026-08-18 from WO4.0.0-019 PARTIAL)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/cluster-rotation`)
**Priority:** P2 · Effort M · Risk M (protocol change; cluster is BETA)
**Scope:** `picosentry/sandbox/cluster/{orchestrator.py,state.py,token_store.py}`, `tests/sandbox/test_cluster*.py`

**Gate:** `bash scripts/test.sh fast` + 3-node rotation test (announce → adopt → old token retires after grace) + snapshot still carries no secret material + compatibility note for rolling upgrades.

## Objective
Token rotation without config redistribution: HMAC-with-primary announcements over gossip, plus the two remaining trust ceilings.

## Evidence (carried, verified 2026-08-17; WO5.0.0-004 fixed the gossip-401 seam 2026-08-18)
1. Digest-only snapshots (landed) cannot carry new token material — rotation via gossip deliberately disabled; today rotate = manual config distribution on every node.
2. `check_hostname=False` ceiling (orchestrator.py:452, documented) — TLS hostname verification off for peer fetches.
3. JSONL runtime store is append-only between full rewrites — no compaction (state grows unbounded between restarts on long-lived clusters).

## Deliverables
1. Rotation announcements: new primary announced as `HMAC(new_primary, old_primary)` over the gossip snapshot; adoption policy decision (quorum vs any-member); grace retirement via existing `retire_stale_tokens`.
2. Hostname-verification path (config-gated; keep the documented ceiling if CA story is out of scope).
3. JSONL compaction between rewrites (bounded rewrite frequency already capped by max_jobs).
