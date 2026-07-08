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


_cluster_manager: ClusterManager | None = None
_cluster_lock = threading.Lock()


def get_cluster_manager() -> ClusterManager:
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
    cluster_token: str = "",
    tls_cert_path: str = "",
    tls_key_path: str = "",
    tls_ca_path: str = "",
) -> ClusterManager:
    global _cluster_manager

    import logging

    logging.getLogger("picodome.cluster").warning(
        "Cluster/gossip configuration is BETA and not recommended for production use."
    )

    _cluster_manager = ClusterManager(
        address=address,
        port=port,
        node_id=node_id,
        backend=backend,
        heartbeat_interval=heartbeat_interval,
        heartbeat_timeout=heartbeat_timeout,
        max_missed_heartbeats=max_missed_heartbeats,
        cluster_token=cluster_token,
        tls_cert_path=tls_cert_path,
        tls_key_path=tls_key_path,
        tls_ca_path=tls_ca_path,
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
