# PicoSentry `cluster mode` Security Review

**Scope:** Multi-node daemon gossip cluster (`picosentry/sandbox/cluster/` and
`picosentry/sandbox/cli_commands/cluster.py`).
**Date:** 2026-07-06
**Status:** Beta — gossip membership and leader election work in a 3-node
integration test, but the protocol has not been formally reviewed for
production network partitions or hostile peers.

## Reviewed areas

| Area | Verdict | Notes |
|------|---------|-------|
| Membership secret | PASS | `PICODOME_CLUSTER_TOKEN` is required; manager does not start without it. |
| mTLS optional | PASS | `--tls-cert`, `--tls-key`, `--tls-ca` enable transport-layer auth and confidentiality. |
| State backend choice | PASS | `memory` (default) or `sqlite` backends selectable. |
| Leader election | PASS | Single-node bootstrap auto-elects; tests exercise leader handoff. |
| Audit logging | PASS | Cluster start/stop and scan assignment emit audit events. |
| CLI surface | PASS | `join`, `status`, `leave` subcommands are scoped and documented. |

## Honest limitations (Enterprise blockers unless accepted as risk)

- **No formal protocol review.** The gossip/heartbeat protocol has not been
  reviewed for Byzantine-fault tolerance, network-partition behavior, or
  hostile-peer attacks. It is currently a best-effort shared-state merge.
- **Token rotation is graceful but not automatic.** `picodome cluster
  rotate-token` updates the local primary token and propagates it via gossip,
  but operators must still trigger retirement of old tokens. There is no
  per-node mTLS identity or certificate pinning yet.
- **State merge is optimistic.** `ClusterState.merge_state()` merges peer
  snapshots without strong conflict resolution. A split-brain scenario can
  produce inconsistent cluster state.
- **No network segmentation controls.** There is no allowlist for peer IP
  ranges or ASN-based binding.
- **Only 3-node integration test.** Real multi-host, multi-region, or WAN
  deployments have not been validated in CI.
- **Experimental warnings in code.** `setup_cluster_manager()` and
  `ClusterManager.start()` log "EXPERIMENTAL" warnings, which is inconsistent
  with the declared **Beta** maturity in `picosentry/experimental.py`.

## Regression tests

- `tests/sandbox/test_cluster.py` — membership, token enforcement, leader
  election, scan redistribution.
- `tests/sandbox/test_cluster_3node.py` — 3-node integration test.

Run the focused suite:

```bash
uv run pytest tests/sandbox/test_cluster.py tests/sandbox/test_cluster_3node.py -q
```

## Graduation criteria to Stable

- ✅ Implement token rotation and multi-token acceptance so rolling updates do
  not partition the cluster. Per-node mTLS identities remain a future
  hardening option.
- Add network-segmentation controls (peer allowlist / bind interface) and
  document expected topology.
- Define and test partition / split-brain behavior explicitly (e.g. majority
  quorum for leader election).
- ✅ Add a cluster operations section to `docs/ops/runbook.md` covering
  deployment, node add/remove, token rotation, and disaster recovery.
- Update the in-code warnings from "EXPERIMENTAL" to "BETA" to match
  `picosentry/experimental.py`.
- Validate a real multi-host deployment before declaring Stable.
