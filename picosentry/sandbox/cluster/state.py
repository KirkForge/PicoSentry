"""ClusterState — node registry, scan queue, leader election, state sync.

Extracted in v2.1.0 (refactor) from ``picosentry/sandbox/cluster/manager.py``.

Provides the higher-level state operations on top of a :class:`StateBackend`:

- Node registry (add, remove, get, list)
- Distributed scan queue with deterministic least-loaded assignment
- State synchronization (gossip-style snapshot + merge)
- Leader election (lowest node_id wins)
"""
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
    """Manages shared cluster state through a state backend.

    Provides:
    - Node registry (add, remove, get, list nodes)
    - Distributed scan queue (assign scans to least-loaded node)
    - State synchronization (gossip-style or HTTP sync)
    - Leader election (simple: lowest node_id wins)
    """

    def __init__(self, backend: StateBackend | None = None) -> None:
        self._backend = backend or MemoryStateBackend()
        self._lock = threading.Lock()

    @property
    def backend(self) -> StateBackend:
        return self._backend

    # ── Node registry ──────────────────────────────────────────────────

    def add_node(self, node: ClusterNode) -> None:
        """Register a node in the cluster."""
        with self._lock:
            self._backend.save_node(node)
        logger.info("Node registered: %s at %s:%d", node.node_id, node.address, node.port)

    def remove_node(self, node_id: str) -> None:
        """Remove a node from the cluster."""
        with self._lock:
            node = self._backend.load_node(node_id)
            self._backend.delete_node(node_id)
        if node:
            logger.info("Node removed: %s", node_id)

    def get_node(self, node_id: str) -> ClusterNode | None:
        """Get a node by ID."""
        return self._backend.load_node(node_id)

    def list_nodes(self, status: NodeStatus | None = None) -> list[ClusterNode]:
        """List all nodes, optionally filtered by status."""
        nodes = self._backend.load_all_nodes()
        if status is not None:
            nodes = [n for n in nodes if n.status == status]
        # Deterministic ordering: sort by node_id
        return sorted(nodes, key=lambda n: n.node_id)

    def update_node(self, node: ClusterNode) -> None:
        """Update a node's state."""
        self._backend.save_node(node)

    # ── Scan queue ──────────────────────────────────────────────────────

    def add_scan(self, scan: ScanRequest) -> None:
        """Add a scan request to the distributed queue."""
        with self._lock:
            self._backend.save_scan(scan)
        logger.info("Scan queued: %s", scan.scan_id)

    def assign_scan(self, scan_id: str) -> ClusterNode | None:
        """Assign a scan to the least-loaded online node.

        Deterministic: nodes sorted by (load, node_id) so the same
        state always produces the same assignment.
        """
        with self._lock:
            scan = self._backend.load_scan(scan_id)
            if scan is None:
                logger.warning("Scan not found: %s", scan_id)
                return None

            if scan.assigned_node is not None:
                # Already assigned
                node = self._backend.load_node(scan.assigned_node)
                return node

            # Find least-loaded online node (deterministic: sort by load, then node_id)
            online_nodes = [n for n in self._backend.load_all_nodes() if n.status == NodeStatus.ONLINE]
            if not online_nodes:
                logger.warning("No online nodes available for scan %s", scan_id)
                return None

            # Sort by (load, node_id) for deterministic assignment
            online_nodes.sort(key=lambda n: (n.load, n.node_id))
            target = online_nodes[0]

            # Update scan and node
            scan.assigned_node = target.node_id
            scan.status = "running"
            target.load += 1

            self._backend.save_scan(scan)
            self._backend.save_node(target)

        logger.info("Scan %s assigned to node %s (load: %d)", scan_id, target.node_id, target.load)
        return target

    def complete_scan(self, scan_id: str, node_id: str) -> None:
        """Mark a scan as completed and decrement node load."""
        with self._lock:
            scan = self._backend.load_scan(scan_id)
            if scan is None:
                return

            scan.status = "completed"
            self._backend.save_scan(scan)

            node = self._backend.load_node(node_id)
            if node and node.load > 0:
                node.load -= 1
                self._backend.save_node(node)

        logger.info("Scan %s completed on node %s", scan_id, node_id)

    def fail_scan(self, scan_id: str) -> None:
        """Mark a scan as failed (will be reassigned)."""
        with self._lock:
            scan = self._backend.load_scan(scan_id)
            if scan is None:
                return

            old_node = scan.assigned_node
            scan.status = "pending"
            scan.assigned_node = None
            self._backend.save_scan(scan)

            # Decrement load on the old node
            if old_node:
                node = self._backend.load_node(old_node)
                if node and node.load > 0:
                    node.load -= 1
                    self._backend.save_node(node)

        logger.info("Scan %s failed (was on node %s), reassigned to pending", scan_id, old_node)

    def get_pending_scans(self) -> list[ScanRequest]:
        """Get all pending (unassigned) scans."""
        scans = self._backend.load_all_scans()
        return [s for s in scans if s.status == "pending"]

    def get_scans_for_node(self, node_id: str) -> list[ScanRequest]:
        """Get all scans assigned to a specific node."""
        scans = self._backend.load_all_scans()
        return [s for s in scans if s.assigned_node == node_id]

    # ── Leader election ─────────────────────────────────────────────────

    def elect_leader(self) -> str | None:
        """Elect a leader: lowest node_id among online nodes wins.

        Deterministic: same set of online nodes always produces same leader.
        """
        online_nodes = self.list_nodes(status=NodeStatus.ONLINE)
        if not online_nodes:
            return None

        # Lowest node_id wins
        leader = online_nodes[0]  # already sorted by node_id
        self._backend.set_leader_id(leader.node_id)
        logger.info("Leader elected: %s", leader.node_id)
        return leader.node_id

    def get_leader_id(self) -> str | None:
        """Get the current leader node ID."""
        return self._backend.get_leader_id()

    # ── State sync ──────────────────────────────────────────────────────

    def get_state_snapshot(self) -> dict[str, Any]:
        """Get a full snapshot of cluster state for synchronization."""
        with self._lock:
            nodes = self._backend.load_all_nodes()
            scans = self._backend.load_all_scans()
            leader_id = self._backend.get_leader_id()
            return {
                "nodes": [n.to_dict() for n in nodes],
                "scans": [s.to_dict() for s in scans],
                "leader_id": leader_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }

    def merge_state(self, snapshot: dict[str, Any]) -> None:
        """Merge a state snapshot from a peer (gossip-style).

        For nodes: keep the one with the most recent heartbeat.
        For scans: keep the one with the most recent status change.
        This is a simple last-writer-wins strategy.
        """
        with self._lock:
            # Merge nodes: remote wins if heartbeat is newer
            for node_data in snapshot.get("nodes", []):
                remote_node = ClusterNode.from_dict(node_data)
                local_node = self._backend.load_node(remote_node.node_id)
                if local_node is None or remote_node.last_heartbeat >= local_node.last_heartbeat:
                    self._backend.save_node(remote_node)

            # Merge scans: remote wins if status is more advanced
            for scan_data in snapshot.get("scans", []):
                remote_scan = ScanRequest.from_dict(scan_data)
                local_scan = self._backend.load_scan(remote_scan.scan_id)
                if local_scan is None:
                    self._backend.save_scan(remote_scan)
                else:
                    # Priority: completed > running > pending (failed resets to pending)
                    status_order = {"completed": 3, "running": 2, "pending": 1, "failed": 0}
                    remote_priority = status_order.get(remote_scan.status, 0)
                    local_priority = status_order.get(local_scan.status, 0)
                    if remote_priority >= local_priority:
                        self._backend.save_scan(remote_scan)

            # Merge leader
            remote_leader = snapshot.get("leader_id")
            if remote_leader:
                self._backend.set_leader_id(remote_leader)

        logger.info(
            "Merged state snapshot from peer (%d nodes, %d scans)",
            len(snapshot.get("nodes", [])),
            len(snapshot.get("scans", [])),
        )


__all__ = ["ClusterState"]
