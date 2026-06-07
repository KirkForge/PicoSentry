"""PicoDome Cluster Manager — v2.1.0 back-compat shim.

The original ``picosentry/sandbox/cluster/manager.py`` was 1050 lines. v2.1.0
splits it into a subpackage:

- ``picosentry.sandbox.cluster.models``        — ``NodeStatus``, ``ClusterNode``,
  ``ScanRequest``, ``DEFAULT_CLUSTER_PORT``, ``DEFAULT_HEARTBEAT_INTERVAL``,
  ``DEFAULT_HEARTBEAT_TIMEOUT``, ``DEFAULT_MAX_MISSED_HEARTBEATS``
- ``picosentry.sandbox.cluster.backends``      — ``StateBackend``,
  ``MemoryStateBackend``, ``SQLiteStateBackend``
- ``picosentry.sandbox.cluster.state``         — ``ClusterState``
- ``picosentry.sandbox.cluster.orchestrator``  — ``ClusterManager``,
  ``_parse_iso_timestamp``

This file is now a thin re-export shim plus the module-level singleton
state (``_cluster_manager``, ``_cluster_lock``, ``get_cluster_manager``,
``setup_cluster_manager``). Tests that import private symbols
(``_cluster_manager``, ``_parse_iso_timestamp``) or that reset the singleton
via ``import picosentry.sandbox.cluster.manager; mgr_mod._cluster_manager = None``
continue to work unchanged.

The shim is on the deprecation path for v2.2.0: new code should import from
``picosentry.sandbox.cluster`` (the package) or from
``picosentry.sandbox.cluster.<submodule>`` directly.
"""
from __future__ import annotations

import threading

from picosentry.sandbox.cluster.backends import (
    MemoryStateBackend,
    SQLiteStateBackend,
    StateBackend,
)
from picosentry.sandbox.cluster.models import (
    DEFAULT_CLUSTER_PORT,
    DEFAULT_HEARTBEAT_INTERVAL,
    DEFAULT_HEARTBEAT_TIMEOUT,
    DEFAULT_MAX_MISSED_HEARTBEATS,
    ClusterNode,
    NodeStatus,
    ScanRequest,
)
from picosentry.sandbox.cluster.orchestrator import (
    ClusterManager,
    _parse_iso_timestamp,
)
from picosentry.sandbox.cluster.state import ClusterState

# ─── Module-level singleton (kept here for back-compat) ──────────────────────
#
# Tests reset the singleton via:
#   import picosentry.sandbox.cluster.manager as mgr_mod
#   mgr_mod._cluster_manager = None
# which is why the state lives on THIS module, not on the orchestrator.

_cluster_manager: ClusterManager | None = None
_cluster_lock = threading.Lock()


def get_cluster_manager() -> ClusterManager:
    """Get the global cluster manager (lazy init, thread-safe)."""
    global _cluster_manager
    if _cluster_manager is None:
        with _cluster_lock:
            if _cluster_manager is None:
                _cluster_manager = ClusterManager()
    return _cluster_manager


def setup_cluster_manager(
    address: str = "127.0.0.1",
    port: int = DEFAULT_CLUSTER_PORT,
    node_id: str | None = None,
    backend: StateBackend | None = None,
    heartbeat_interval: int = DEFAULT_HEARTBEAT_INTERVAL,
    heartbeat_timeout: int = DEFAULT_HEARTBEAT_TIMEOUT,
    max_missed_heartbeats: int = DEFAULT_MAX_MISSED_HEARTBEATS,
) -> ClusterManager:
    """Configure and return the global cluster manager."""
    global _cluster_manager
    _cluster_manager = ClusterManager(
        address=address,
        port=port,
        node_id=node_id,
        backend=backend,
        heartbeat_interval=heartbeat_interval,
        heartbeat_timeout=heartbeat_timeout,
        max_missed_heartbeats=max_missed_heartbeats,
    )
    return _cluster_manager


__all__ = [
    "DEFAULT_CLUSTER_PORT",
    "DEFAULT_HEARTBEAT_INTERVAL",
    "DEFAULT_HEARTBEAT_TIMEOUT",
    "DEFAULT_MAX_MISSED_HEARTBEATS",
    "ClusterManager",
    "ClusterNode",
    "ClusterState",
    "MemoryStateBackend",
    "NodeStatus",
    "SQLiteStateBackend",
    "ScanRequest",
    "StateBackend",
    "_cluster_lock",
    "_cluster_manager",
    "_parse_iso_timestamp",
    "get_cluster_manager",
    "setup_cluster_manager",
]
