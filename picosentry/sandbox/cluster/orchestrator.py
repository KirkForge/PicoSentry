"""ClusterManager — orchestrator for cluster lifecycle.

Extracted in v2.1.0 (refactor) from ``picosentry/sandbox/cluster/manager.py``.

Drives node registration, heartbeat/health-check loops, scan assignment,
peer state sync, and graceful shutdown. Holds a :class:`ClusterState`
backed by a pluggable :class:`StateBackend`.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any

from picosentry.sandbox.audit import AuditEventType, get_audit_logger
from picosentry.sandbox.cluster.backends.base import StateBackend
from picosentry.sandbox.cluster.models import (
    DEFAULT_CLUSTER_PORT,
    DEFAULT_HEARTBEAT_INTERVAL,
    DEFAULT_HEARTBEAT_TIMEOUT,
    DEFAULT_MAX_MISSED_HEARTBEATS,
    ClusterNode,
    NodeStatus,
    ScanRequest,
)
from picosentry.sandbox.cluster.state import ClusterState

logger = logging.getLogger("picodome.cluster")


def _parse_iso_timestamp(ts: str) -> float | None:
    """Parse an ISO 8601 timestamp to seconds since epoch.

    Returns None if parsing fails.
    """
    try:
        # Handle both Z and +00:00 suffixes
        ts = ts.replace("Z", "+00:00")
        from datetime import datetime

        dt = datetime.fromisoformat(ts)
        return dt.timestamp()
    except (ValueError, TypeError):
        # Fallback: try time.strptime
        try:
            import calendar

            t = time.strptime(ts.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
            return calendar.timegm(t)
        except (ValueError, TypeError):
            return None


class ClusterManager:
    """Orchestrates cluster lifecycle: join, leave, heartbeat, failover.

    Usage::

        manager = ClusterManager(address="10.0.0.1", port=8444)
        manager.start()  # register self, begin heartbeats
        ...
        node = manager.assign_scan(scan_request)
        ...
        manager.stop()  # graceful shutdown, drain scans, deregister
    """

    def __init__(
        self,
        address: str = "127.0.0.1",
        port: int = DEFAULT_CLUSTER_PORT,
        node_id: str | None = None,
        backend: StateBackend | None = None,
        heartbeat_interval: int = DEFAULT_HEARTBEAT_INTERVAL,
        heartbeat_timeout: int = DEFAULT_HEARTBEAT_TIMEOUT,
        max_missed_heartbeats: int = DEFAULT_MAX_MISSED_HEARTBEATS,
    ) -> None:
        self._address = address
        self._port = port
        self._node_id = node_id or ClusterNode.generate_id()
        self._state = ClusterState(backend)
        self._heartbeat_interval = heartbeat_interval
        self._heartbeat_timeout = heartbeat_timeout
        self._max_missed_heartbeats = max_missed_heartbeats
        self._running = False
        self._heartbeat_thread: threading.Thread | None = None
        self._health_check_thread: threading.Thread | None = None
        self._stop_event: threading.Event = threading.Event()

    @property
    def node_id(self) -> str:
        return self._node_id

    @property
    def state(self) -> ClusterState:
        return self._state

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start cluster mode: register self, begin heartbeat loop."""
        self._stop_event.clear()
        if self._running:
            logger.warning("Cluster manager already running")
            return

        self._running = True

        # Register self
        self_node = ClusterNode(
            node_id=self._node_id,
            address=self._address,
            port=self._port,
            status=NodeStatus.ONLINE,
            last_heartbeat=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            load=0,
        )
        self._state.add_node(self_node)

        # Elect leader if we're the only node
        if len(self._state.list_nodes(status=NodeStatus.ONLINE)) == 1:
            self._state.elect_leader()

        # Start heartbeat thread
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
            name="picodome-cluster-heartbeat",
        )
        self._heartbeat_thread.start()

        # Start health check thread
        self._health_check_thread = threading.Thread(
            target=self._health_check_loop,
            daemon=True,
            name="picodome-cluster-health",
        )
        self._health_check_thread.start()

        # Audit
        try:
            audit = get_audit_logger()
            audit.record(
                event_type=AuditEventType.DAEMON_START,
                actor=f"cluster-{self._node_id}",
                detail=f"Cluster node started at {self._address}:{self._port}",
            )
        except Exception:
            pass

        logger.info("Cluster node %s started at %s:%d", self._node_id, self._address, self._port)

    def stop(self) -> None:
        """Graceful shutdown: drain scans, deregister, stop heartbeat."""
        if not self._running:
            return

        self._running = False
        self._stop_event.set()

        # Set status to draining while we finish in-progress scans
        node = self._state.get_node(self._node_id)
        if node:
            node.status = NodeStatus.DRAINING
            self._state.update_node(node)

        # Wait briefly for in-progress scans to complete
        # (In production, this would wait for actual scan completion)
        time.sleep(0.1)

        # Deregister: set offline and remove
        if node:
            node.status = NodeStatus.OFFLINE
            self._state.update_node(node)

        # Wait for background threads to finish (with timeout)
        for thread in (self._heartbeat_thread, self._health_check_thread):
            if thread is not None and thread.is_alive():
                thread.join(timeout=5.0)

        # Remove self from cluster
        self._state.remove_node(self._node_id)

        # Re-elect leader if we were the leader
        leader_id = self._state.get_leader_id()
        if leader_id == self._node_id or leader_id is None:
            self._state.elect_leader()

        # Audit
        try:
            audit = get_audit_logger()
            audit.record(
                event_type=AuditEventType.DAEMON_STOP,
                actor=f"cluster-{self._node_id}",
                detail="Cluster node stopped",
            )
        except Exception:
            pass

        logger.info("Cluster node %s stopped", self._node_id)

    # ── Scan assignment ──────────────────────────────────────────────────

    def assign_scan(self, scan_request: ScanRequest) -> ClusterNode | None:
        """Find the best node for a scan (least-loaded online node).

        Returns the assigned ClusterNode, or None if no nodes available.
        """
        # Add scan to state
        self._state.add_scan(scan_request)

        # Assign to least-loaded node
        node = self._state.assign_scan(scan_request.scan_id)

        # Audit
        if node:
            try:
                audit = get_audit_logger()
                audit.record(
                    event_type=AuditEventType.SCAN_START,
                    actor=f"cluster-{self._node_id}",
                    detail=f"Scan {scan_request.scan_id} assigned to {node.node_id}",
                    target=scan_request.scan_id,
                    metadata={"command": scan_request.command, "assigned_node": node.node_id},
                )
            except Exception:
                pass

        return node

    # ── State synchronization ───────────────────────────────────────────

    def sync_state(self) -> dict[str, Any]:
        """Get cluster state snapshot for synchronization with peers.

        Returns a dict that can be serialized and sent to other nodes.
        """
        return self._state.get_state_snapshot()

    def merge_peer_state(self, snapshot: dict[str, Any]) -> None:
        """Merge state from a peer node.

        Gossip-style: last-writer-wins for nodes, status-priority for scans.
        """
        self._state.merge_state(snapshot)

    # ── Heartbeat handling ──────────────────────────────────────────────

    def handle_heartbeat(self, node_id: str, status: str = "online", load: int = 0) -> ClusterNode | None:
        """Process a heartbeat from a peer node.

        Updates the node's status, last_heartbeat, and load.
        Returns the updated node, or None if node is not registered.
        """
        node = self._state.get_node(node_id)
        if node is None:
            logger.warning("Heartbeat from unknown node: %s", node_id)
            return None

        node.status = NodeStatus(status) if isinstance(status, str) else status
        node.last_heartbeat = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        node.load = load
        self._state.update_node(node)

        logger.debug("Heartbeat from %s: status=%s load=%d", node_id, status, load)
        return node

    # ── Node failure handling ────────────────────────────────────────────

    def handle_node_failure(self, node_id: str) -> list[str]:
        """Handle a node failure: redistribute its scans to other nodes.

        Returns list of scan IDs that were redistributed.
        Scans are never lost — they are moved back to pending and reassigned.
        """
        node = self._state.get_node(node_id)
        if node is None:
            logger.warning("Node failure for unknown node: %s", node_id)
            return []

        # Mark node as offline
        node.status = NodeStatus.OFFLINE
        self._state.update_node(node)

        # Find all scans assigned to this node
        failed_scans = self._state.get_scans_for_node(node_id)
        redistributed = []

        for scan in failed_scans:
            # Reset scan to pending
            self._state.fail_scan(scan.scan_id)
            redistributed.append(scan.scan_id)

            # Re-assign to another node
            new_node = self._state.assign_scan(scan.scan_id)
            if new_node:
                logger.info("Scan %s redistributed from %s to %s", scan.scan_id, node_id, new_node.node_id)
            else:
                logger.warning("No available node for scan %s (was on failed node %s)", scan.scan_id, node_id)

        # Audit
        try:
            audit = get_audit_logger()
            audit.record(
                event_type=AuditEventType.SCAN_ALERT,
                actor=f"cluster-{self._node_id}",
                detail=f"Node {node_id} failed, {len(redistributed)} scans redistributed",
                target=node_id,
                metadata={"redistributed_scans": redistributed},
            )
        except Exception:
            pass

        logger.info("Node %s failed: %d scans redistributed", node_id, len(redistributed))
        return redistributed

    # ── Cluster status ──────────────────────────────────────────────────

    def get_status(self) -> dict[str, Any]:
        """Get cluster status summary."""
        nodes = self._state.list_nodes()
        online_nodes = [n for n in nodes if n.status == NodeStatus.ONLINE]
        offline_nodes = [n for n in nodes if n.status == NodeStatus.OFFLINE]
        draining_nodes = [n for n in nodes if n.status == NodeStatus.DRAINING]

        scans = self._state.backend.load_all_scans()
        pending = [s for s in scans if s.status == "pending"]
        running = [s for s in scans if s.status == "running"]
        completed = [s for s in scans if s.status == "completed"]

        return {
            "self_id": self._node_id,
            "leader_id": self._state.get_leader_id(),
            "nodes_total": len(nodes),
            "nodes_online": len(online_nodes),
            "nodes_offline": len(offline_nodes),
            "nodes_draining": len(draining_nodes),
            "scans_total": len(scans),
            "scans_pending": len(pending),
            "scans_running": len(running),
            "scans_completed": len(completed),
            "nodes": [n.to_dict() for n in nodes],
        }

    # ── Background loops ────────────────────────────────────────────────

    def _heartbeat_loop(self) -> None:
        """Periodically update own heartbeat in the cluster state."""
        while self._running:
            try:
                node = self._state.get_node(self._node_id)
                if node:
                    node.last_heartbeat = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    self._state.update_node(node)
            except Exception as e:
                logger.error("Heartbeat update failed: %s", e)

            self._stop_event.wait(timeout=self._heartbeat_interval)

    def _health_check_loop(self) -> None:
        """Periodically check node health and handle failures.

        A node is considered offline after missing max_missed_heartbeats
        heartbeats (each heartbeat_timeout seconds apart).
        """
        while self._running:
            try:
                self._check_node_health()
            except Exception as e:
                logger.error("Health check failed: %s", e)

            self._stop_event.wait(timeout=self._heartbeat_timeout)

    def _check_node_health(self) -> None:
        """Check all nodes for heartbeat timeout and mark offline if needed."""
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        now_ts = _parse_iso_timestamp(now)
        timeout_seconds = self._heartbeat_timeout * self._max_missed_heartbeats

        nodes = self._state.list_nodes(status=NodeStatus.ONLINE)
        for node in nodes:
            if node.node_id == self._node_id:
                continue  # Skip self

            if not node.last_heartbeat:
                continue  # No heartbeat yet, give benefit of doubt

            heartbeat_ts = _parse_iso_timestamp(node.last_heartbeat)
            if heartbeat_ts is None:
                continue

            elapsed = (now_ts or 0) - heartbeat_ts
            if elapsed > timeout_seconds:
                logger.warning(
                    "Node %s missed %d heartbeats (elapsed: %ds), marking offline",
                    node.node_id,
                    self._max_missed_heartbeats,
                    int(elapsed),
                )
                self.handle_node_failure(node.node_id)


__all__ = ["ClusterManager", "_parse_iso_timestamp"]
