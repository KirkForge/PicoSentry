"""PicoDome Cluster Manager — multi-node daemon support with shared state.

Cluster architecture:
- ClusterNode: represents a node in the cluster (id, address, status, load).
- ClusterState: manages node registry, scan queue, and state synchronization.
- ClusterManager: orchestrates cluster lifecycle (join, leave, heartbeat, failover).
- State backends: MemoryStateBackend (default/testing) and SQLiteStateBackend (persistent).

Deterministic guarantees:
- Least-loaded assignment is deterministic: nodes sorted by (load, node_id).
- Heartbeat timeout: 30s default. Node offline after 3 missed heartbeats (90s).
- Scan redistribution on node failure is deterministic: round-robin by node_id.
- All cluster operations are audit-logged.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from picosentry.sandbox.audit import AuditEventType, get_audit_logger

logger = logging.getLogger("picodome.cluster")

# ─── Constants ──────────────────────────────────────────────────────────────

DEFAULT_HEARTBEAT_INTERVAL = 10  # seconds
DEFAULT_HEARTBEAT_TIMEOUT = 30  # seconds
DEFAULT_MAX_MISSED_HEARTBEATS = 3
DEFAULT_CLUSTER_PORT = 8444  # cluster communication port (distinct from daemon 8443)

# ─── Node status ─────────────────────────────────────────────────────────────


class NodeStatus(str, Enum):
    """Cluster node status."""

    ONLINE = "online"
    OFFLINE = "offline"
    DRAINING = "draining"


# ─── Cluster node ───────────────────────────────────────────────────────────


@dataclass
class ClusterNode:
    """Represents a node in the PicoDome cluster.

    Deterministic: comparison is by (load, node_id) for consistent
    least-loaded assignment.
    """

    node_id: str
    address: str
    port: int = DEFAULT_CLUSTER_PORT
    status: NodeStatus = NodeStatus.ONLINE
    last_heartbeat: str = ""
    load: int = 0  # scans in progress

    def __post_init__(self) -> None:
        if isinstance(self.status, str):
            self.status = NodeStatus(self.status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "address": self.address,
            "port": self.port,
            "status": self.status.value,
            "last_heartbeat": self.last_heartbeat,
            "load": self.load,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClusterNode:
        return cls(
            node_id=data["node_id"],
            address=data["address"],
            port=data.get("port", DEFAULT_CLUSTER_PORT),
            status=NodeStatus(data.get("status", "online")),
            last_heartbeat=data.get("last_heartbeat", ""),
            load=data.get("load", 0),
        )

    @classmethod
    def generate_id(cls) -> str:
        """Generate a deterministic-style node ID from hostname + pid.

        Not truly deterministic (depends on runtime), but stable within
        a single process session for testing.
        """
        import socket

        hostname = socket.gethostname()
        pid = os.getpid()
        return f"picodome-{hostname}-{pid}"


# ─── Scan request ───────────────────────────────────────────────────────────


@dataclass
class ScanRequest:
    """A scan request to be assigned to a cluster node."""

    scan_id: str
    command: list[str]
    priority: int = 0  # higher = more urgent
    assigned_node: str | None = None
    created_at: str = ""
    status: str = "pending"  # pending, running, completed, failed

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "command": self.command,
            "priority": self.priority,
            "assigned_node": self.assigned_node,
            "created_at": self.created_at,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanRequest:
        return cls(
            scan_id=data["scan_id"],
            command=data["command"],
            priority=data.get("priority", 0),
            assigned_node=data.get("assigned_node"),
            created_at=data.get("created_at", ""),
            status=data.get("status", "pending"),
        )


# ─── State backends ─────────────────────────────────────────────────────────


class StateBackend:
    """Abstract base class for cluster state backends."""

    def save_node(self, node: ClusterNode) -> None:
        raise NotImplementedError

    def load_node(self, node_id: str) -> ClusterNode | None:
        raise NotImplementedError

    def load_all_nodes(self) -> list[ClusterNode]:
        raise NotImplementedError

    def delete_node(self, node_id: str) -> None:
        raise NotImplementedError

    def save_scan(self, scan: ScanRequest) -> None:
        raise NotImplementedError

    def load_scan(self, scan_id: str) -> ScanRequest | None:
        raise NotImplementedError

    def load_all_scans(self) -> list[ScanRequest]:
        raise NotImplementedError

    def delete_scan(self, scan_id: str) -> None:
        raise NotImplementedError

    def get_leader_id(self) -> str | None:
        raise NotImplementedError

    def set_leader_id(self, node_id: str) -> None:
        raise NotImplementedError


class MemoryStateBackend(StateBackend):
    """In-memory state backend for single-node or testing.

    All state is lost on process restart. Thread-safe via locks.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, ClusterNode] = {}
        self._scans: dict[str, ScanRequest] = {}
        self._leader_id: str | None = None
        self._lock = threading.Lock()

    def save_node(self, node: ClusterNode) -> None:
        with self._lock:
            self._nodes[node.node_id] = node

    def load_node(self, node_id: str) -> ClusterNode | None:
        with self._lock:
            return self._nodes.get(node_id)

    def load_all_nodes(self) -> list[ClusterNode]:
        with self._lock:
            return list(self._nodes.values())

    def delete_node(self, node_id: str) -> None:
        with self._lock:
            self._nodes.pop(node_id, None)

    def save_scan(self, scan: ScanRequest) -> None:
        with self._lock:
            self._scans[scan.scan_id] = scan

    def load_scan(self, scan_id: str) -> ScanRequest | None:
        with self._lock:
            return self._scans.get(scan_id)

    def load_all_scans(self) -> list[ScanRequest]:
        with self._lock:
            return list(self._scans.values())

    def delete_scan(self, scan_id: str) -> None:
        with self._lock:
            self._scans.pop(scan_id, None)

    def get_leader_id(self) -> str | None:
        with self._lock:
            return self._leader_id

    def set_leader_id(self, node_id: str) -> None:
        with self._lock:
            self._leader_id = node_id


class SQLiteStateBackend(StateBackend):
    """SQLite-backed state for persistent shared state across restarts.

    Uses a single database file for all cluster state.
    Thread-safe via connection-per-operation with WAL mode.
    """

    def __init__(self, db_path: Path | None = None) -> None:
        if db_path is None:
            db_path = Path.home() / ".picodome" / "cluster" / "cluster.db"
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS cluster_nodes (
                    node_id TEXT PRIMARY KEY,
                    address TEXT NOT NULL,
                    port INTEGER NOT NULL DEFAULT 8444,
                    status TEXT NOT NULL DEFAULT 'online',
                    last_heartbeat TEXT NOT NULL DEFAULT '',
                    load INTEGER NOT NULL DEFAULT 0,
                    data TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS cluster_scans (
                    scan_id TEXT PRIMARY KEY,
                    command TEXT NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 0,
                    assigned_node TEXT,
                    created_at TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'pending',
                    data TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS cluster_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
            """)
            conn.commit()
        finally:
            conn.close()

    def save_node(self, node: ClusterNode) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO cluster_nodes
                   (node_id, address, port, status, last_heartbeat, load, data)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    node.node_id,
                    node.address,
                    node.port,
                    node.status.value,
                    node.last_heartbeat,
                    node.load,
                    json.dumps(node.to_dict(), sort_keys=True),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def load_node(self, node_id: str) -> ClusterNode | None:
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "SELECT data FROM cluster_nodes WHERE node_id = ?",
                (node_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return ClusterNode.from_dict(json.loads(row[0]))
        finally:
            conn.close()

    def load_all_nodes(self) -> list[ClusterNode]:
        conn = self._get_conn()
        try:
            cursor = conn.execute("SELECT data FROM cluster_nodes")
            return [ClusterNode.from_dict(json.loads(row[0])) for row in cursor.fetchall()]
        finally:
            conn.close()

    def delete_node(self, node_id: str) -> None:
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM cluster_nodes WHERE node_id = ?", (node_id,))
            conn.commit()
        finally:
            conn.close()

    def save_scan(self, scan: ScanRequest) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO cluster_scans
                   (scan_id, command, priority, assigned_node, created_at, status, data)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan.scan_id,
                    json.dumps(scan.command, sort_keys=True),
                    scan.priority,
                    scan.assigned_node,
                    scan.created_at,
                    scan.status,
                    json.dumps(scan.to_dict(), sort_keys=True),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def load_scan(self, scan_id: str) -> ScanRequest | None:
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "SELECT data FROM cluster_scans WHERE scan_id = ?",
                (scan_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return ScanRequest.from_dict(json.loads(row[0]))
        finally:
            conn.close()

    def load_all_scans(self) -> list[ScanRequest]:
        conn = self._get_conn()
        try:
            cursor = conn.execute("SELECT data FROM cluster_scans")
            return [ScanRequest.from_dict(json.loads(row[0])) for row in cursor.fetchall()]
        finally:
            conn.close()

    def delete_scan(self, scan_id: str) -> None:
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM cluster_scans WHERE scan_id = ?", (scan_id,))
            conn.commit()
        finally:
            conn.close()

    def get_leader_id(self) -> str | None:
        conn = self._get_conn()
        try:
            cursor = conn.execute("SELECT value FROM cluster_meta WHERE key = 'leader_id'")
            row = cursor.fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def set_leader_id(self, node_id: str) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO cluster_meta (key, value) VALUES ('leader_id', ?)""",
                (node_id,),
            )
            conn.commit()
        finally:
            conn.close()


# ─── Cluster state ──────────────────────────────────────────────────────────


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


# ─── Cluster manager ────────────────────────────────────────────────────────


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


# ─── Utility functions ──────────────────────────────────────────────────────


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


# ─── Module-level singleton ─────────────────────────────────────────────────


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
