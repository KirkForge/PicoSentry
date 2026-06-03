"""PicoDome Cluster — multi-node daemon support with shared state.

Provides cluster node registry, distributed scan assignment,
heartbeat-based health checks, and state synchronization.

Design principles:
- Deterministic: cluster state must be consistent across nodes.
- Scans are never lost: failed nodes have their scans redistributed.
- Simple: no distributed consensus, just heartbeat health + least-loaded assignment.
- Two state backends: MemoryStateBackend (default/testing) and SQLiteStateBackend (persistent).
"""

from __future__ import annotations

from picosentry.sandbox.cluster.manager import (
    ClusterManager,
    ClusterNode,
    ClusterState,
    MemoryStateBackend,
    NodeStatus,
    SQLiteStateBackend,
)

__all__ = [
    "ClusterNode",
    "ClusterState",
    "ClusterManager",
    "MemoryStateBackend",
    "SQLiteStateBackend",
    "NodeStatus",
]
