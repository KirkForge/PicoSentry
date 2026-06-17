from __future__ import annotations

import logging
import threading
import time
from typing import Any

from picosentry.sandbox.cluster.backends.base import StateBackend
from picosentry.sandbox.cluster.backends.memory import MemoryStateBackend
from picosentry.sandbox.cluster.models import ClusterNode, NodeStatus, ScanRequest

logger = logging.getLogger("picodome.cluster")


class ClusterState:

    def __init__(self, backend: StateBackend | None = None, cluster_token: str = "") -> None:
        self._backend = backend or MemoryStateBackend()
        self._lock = threading.Lock()
        self._version_lock = threading.Lock()
        self._cluster_token = cluster_token
        self._version_counter = 0

    @property
    def backend(self) -> StateBackend:
        return self._backend

    @property
    def cluster_token(self) -> str:
        return self._cluster_token

    def set_cluster_token(self, token: str) -> None:
        with self._lock:
            self._cluster_token = token

    def _next_version(self) -> int:
        with self._version_lock:
            self._version_counter += 1
            return self._version_counter

    def add_node(self, node: ClusterNode) -> None:
        if node.version == 0:
            node.version = self._next_version()
        with self._lock:
            self._backend.save_node(node)
        logger.info("Node registered: %s at %s:%d", node.node_id, node.address, node.port)

    def remove_node(self, node_id: str) -> None:
        with self._lock:
            node = self._backend.load_node(node_id)
            self._backend.delete_node(node_id)
        if node:
            logger.info("Node removed: %s", node_id)

    def get_node(self, node_id: str) -> ClusterNode | None:
        return self._backend.load_node(node_id)

    def list_nodes(self, status: NodeStatus | None = None) -> list[ClusterNode]:
        nodes = self._backend.load_all_nodes()
        if status is not None:
            nodes = [n for n in nodes if n.status == status]

        return sorted(nodes, key=lambda n: n.node_id)

    def update_node(self, node: ClusterNode) -> None:
        node.version = self._next_version()
        with self._lock:
            self._backend.save_node(node)

    def add_scan(self, scan: ScanRequest) -> None:
        if scan.version == 0:
            scan.version = self._next_version()
        with self._lock:
            self._backend.save_scan(scan)
        logger.info("Scan queued: %s", scan.scan_id)

    def assign_scan(self, scan_id: str) -> ClusterNode | None:
        with self._lock:
            scan = self._backend.load_scan(scan_id)
            if scan is None:
                logger.warning("Scan not found: %s", scan_id)
                return None

            if scan.assigned_node is not None:

                return self._backend.load_node(scan.assigned_node)


            online_nodes = [n for n in self._backend.load_all_nodes() if n.status == NodeStatus.ONLINE]
            if not online_nodes:
                logger.warning("No online nodes available for scan %s", scan_id)
                return None


            online_nodes.sort(key=lambda n: (n.load, n.node_id))
            target = online_nodes[0]


            scan.assigned_node = target.node_id
            scan.status = "running"
            target.load += 1
            scan.version = self._next_version()
            target.version = self._next_version()

            self._backend.save_scan(scan)
            self._backend.save_node(target)

        logger.info("Scan %s assigned to node %s (load: %d)", scan_id, target.node_id, target.load)
        return target

    def complete_scan(self, scan_id: str, node_id: str) -> None:
        with self._lock:
            scan = self._backend.load_scan(scan_id)
            if scan is None:
                return

            scan.status = "completed"
            scan.version = self._next_version()
            self._backend.save_scan(scan)

            node = self._backend.load_node(node_id)
            if node and node.load > 0:
                node.load -= 1
                node.version = self._next_version()
                self._backend.save_node(node)

        logger.info("Scan %s completed on node %s", scan_id, node_id)

    def fail_scan(self, scan_id: str) -> None:
        with self._lock:
            scan = self._backend.load_scan(scan_id)
            if scan is None:
                return

            old_node = scan.assigned_node
            scan.status = "pending"
            scan.assigned_node = None
            scan.version = self._next_version()
            self._backend.save_scan(scan)


            if old_node:
                node = self._backend.load_node(old_node)
                if node and node.load > 0:
                    node.load -= 1
                    node.version = self._next_version()
                    self._backend.save_node(node)

        logger.info("Scan %s failed (was on node %s), reassigned to pending", scan_id, old_node)

    def get_pending_scans(self) -> list[ScanRequest]:
        scans = self._backend.load_all_scans()
        return [s for s in scans if s.status == "pending"]

    def get_scans_for_node(self, node_id: str) -> list[ScanRequest]:
        scans = self._backend.load_all_scans()
        return [s for s in scans if s.assigned_node == node_id]


    def elect_leader(self) -> str | None:
        online_nodes = self.list_nodes(status=NodeStatus.ONLINE)
        if not online_nodes:
            return None


        leader = online_nodes[0]  # already sorted by node_id
        self._backend.set_leader_id(leader.node_id)
        logger.info("Leader elected: %s", leader.node_id)
        return leader.node_id

    def get_leader_id(self) -> str | None:
        return self._backend.get_leader_id()


    def get_state_snapshot(self) -> dict[str, Any]:
        with self._lock:
            nodes = self._backend.load_all_nodes()
            scans = self._backend.load_all_scans()
            leader_id = self._backend.get_leader_id()
            snapshot: dict[str, Any] = {
                "nodes": [n.to_dict() for n in nodes],
                "scans": [s.to_dict() for s in scans],
                "leader_id": leader_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            if self._cluster_token:
                snapshot["cluster_token"] = self._cluster_token
            return snapshot

    def merge_state(self, snapshot: dict[str, Any]) -> None:
        with self._lock:
            remote_token = snapshot.get("cluster_token")
            if self._cluster_token and remote_token != self._cluster_token:
                raise ValueError("cluster token mismatch")

            def _node_is_newer(remote: ClusterNode, local: ClusterNode) -> bool:
                if remote.version > local.version:
                    return True
                if remote.version == local.version:
                    return remote.last_heartbeat >= local.last_heartbeat
                # remote.version < local.version: a legacy (unversioned) remote record
                # still wins by wall-clock, otherwise the newer version wins.
                if remote.version == 0:
                    return remote.last_heartbeat >= local.last_heartbeat
                return False

            def _scan_is_newer(remote: ScanRequest, local: ScanRequest) -> bool:
                if remote.version > local.version:
                    return True

                status_order = {"completed": 3, "running": 2, "pending": 1, "failed": 0}
                remote_priority = status_order.get(remote.status, 0)
                local_priority = status_order.get(local.status, 0)
                if remote.version == local.version:
                    return remote_priority >= local_priority
                # remote.version < local.version: legacy unversioned record falls
                # back to the original status-priority tie-breaker.
                if remote.version == 0:
                    return remote_priority >= local_priority
                return False

            for node_data in snapshot.get("nodes", []):
                remote_node = ClusterNode.from_dict(node_data)
                local_node = self._backend.load_node(remote_node.node_id)
                if local_node is None or _node_is_newer(remote_node, local_node):
                    self._backend.save_node(remote_node)


            for scan_data in snapshot.get("scans", []):
                remote_scan = ScanRequest.from_dict(scan_data)
                local_scan = self._backend.load_scan(remote_scan.scan_id)
                if local_scan is None or _scan_is_newer(remote_scan, local_scan):
                    self._backend.save_scan(remote_scan)


            # Re-elect after merge so all nodes converge on the same leader
            # (lowest online node_id).  Accepting the remote leader_id
            # directly would cause oscillation when three+ peers exchange
            # snapshots in different orders.
            self.elect_leader()

        logger.info(
            "Merged state snapshot from peer (%d nodes, %d scans)",
            len(snapshot.get("nodes", [])),
            len(snapshot.get("scans", [])),
        )


__all__ = ["ClusterState"]
