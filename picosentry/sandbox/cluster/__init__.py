"""PicoDome Cluster — multi-node daemon support with shared state.

Provides cluster node registry, distributed scan assignment,
heartbeat-based health checks, and state synchronization.

Design principles:
- Deterministic: cluster state must be consistent across nodes.
- Scans are never lost: failed nodes have their scans redistributed.
- Simple: no distributed consensus, just heartbeat health + least-loaded assignment.
- Two state backends: MemoryStateBackend (default/testing) and SQLiteStateBackend (persistent).

Internal layout (v2.1.0 refactor):
- :mod:`picosentry.sandbox.cluster.models`        — dataclasses + constants
- :mod:`picosentry.sandbox.cluster.backends`      — StateBackend + implementations
- :mod:`picosentry.sandbox.cluster.state`         — ClusterState
- :mod:`picosentry.sandbox.cluster.orchestrator`  — ClusterManager
- :mod:`picosentry.sandbox.cluster.manager`       — back-compat shim + singleton
"""
from __future__ import annotations

from picosentry.sandbox.cluster.backends import (
    MemoryStateBackend,
    SQLiteStateBackend,
    StateBackend,
)
from picosentry.sandbox.cluster.manager import (
    ClusterManager,
    ClusterNode,
    ClusterState,
    NodeStatus,
    ScanRequest,
)

__all__ = [
    "ClusterManager",
    "ClusterNode",
    "ClusterState",
    "MemoryStateBackend",
    "NodeStatus",
    "SQLiteStateBackend",
    "ScanRequest",
    "StateBackend",
]
