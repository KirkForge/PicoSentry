"""Tests for PicoDome cluster module — multi-node daemon support with shared state.

Tests cover:
- ClusterNode creation, serialization, and comparison
- ClusterState node registry operations
- ClusterState scan queue and assignment
- ClusterState leader election
- ClusterState state synchronization
- MemoryStateBackend CRUD operations
- SQLiteStateBackend CRUD operations
- ClusterManager lifecycle (start, stop)
- ClusterManager scan assignment
- ClusterManager heartbeat handling
- ClusterManager node failure and scan redistribution
- ClusterManager status reporting
- ScanRequest creation and serialization
- NodeStatus enum
- Edge cases: empty cluster, no online nodes, concurrent access
"""

from __future__ import annotations

import json
import logging
import threading
import time

import pytest

from picosentry.sandbox.cluster.manager import (
    DEFAULT_CLUSTER_PORT,
    ClusterManager,
    ClusterNode,
    ClusterState,
    MemoryStateBackend,
    NodeStatus,
    ScanRequest,
    SQLiteStateBackend,
    _parse_iso_timestamp,
    get_cluster_manager,
    setup_cluster_manager,
)

# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def memory_backend():
    """Fresh in-memory state backend."""
    return MemoryStateBackend()


@pytest.fixture
def sqlite_backend(tmp_path):
    """Fresh SQLite state backend with a temp database."""
    db_path = tmp_path / "test_cluster.db"
    return SQLiteStateBackend(db_path=db_path)


@pytest.fixture
def cluster_state(memory_backend):
    """ClusterState with memory backend."""
    return ClusterState(backend=memory_backend)


@pytest.fixture(params=["memory", "sqlite"])
def any_backend(request, tmp_path):
    """Parametrized fixture yielding a fresh memory or sqlite backend.

    Used by TestStateBackends to exercise the common CRUD contract both
    implementations must satisfy. The two dedicated backend fixtures
    (``memory_backend``, ``sqlite_backend``) stay for tests that need a
    specific backend.
    """
    if request.param == "memory":
        return MemoryStateBackend()
    return SQLiteStateBackend(db_path=tmp_path / f"test_{request.node.name}.db")


@pytest.fixture
def node_a():
    """Test cluster node A."""
    return ClusterNode(
        node_id="node-a",
        address="10.0.0.1",
        port=8444,
        status=NodeStatus.ONLINE,
        last_heartbeat="2026-01-01T00:00:00Z",
        load=0,
    )


@pytest.fixture
def node_b():
    """Test cluster node B."""
    return ClusterNode(
        node_id="node-b",
        address="10.0.0.2",
        port=8444,
        status=NodeStatus.ONLINE,
        last_heartbeat="2026-01-01T00:00:00Z",
        load=2,
    )


@pytest.fixture
def node_c():
    """Test cluster node C with high load."""
    return ClusterNode(
        node_id="node-c",
        address="10.0.0.3",
        port=8444,
        status=NodeStatus.ONLINE,
        last_heartbeat="2026-01-01T00:00:00Z",
        load=5,
    )


@pytest.fixture
def scan_request():
    """A sample scan request."""
    return ScanRequest(
        scan_id="scan-001",
        command=["npm", "install", "express"],
        priority=0,
        created_at="2026-01-01T00:00:00Z",
    )


@pytest.fixture
def manager(memory_backend):
    """ClusterManager with memory backend for testing."""
    return ClusterManager(
        address="127.0.0.1",
        port=8444,
        node_id="test-node",
        backend=memory_backend,
        heartbeat_interval=1,
        heartbeat_timeout=2,
    )


@pytest.fixture
def started_manager(manager):
    """ClusterManager that has been started; stopped automatically after the test.

    Eliminates the ``manager.start(); try: ... finally: manager.stop()`` boilerplate
    that ~10 TestClusterManager tests otherwise repeat. Tests that exercise the
    start/stop transition itself (test_stop_deregisters, test_is_running_flag,
    test_start_idempotent) still use the plain ``manager`` fixture.
    """
    manager.start()
    try:
        yield manager
    finally:
        manager.stop()


# ─── ClusterNode tests ──────────────────────────────────────────────────────


class TestClusterNode:
    """Tests for ClusterNode dataclass."""

    def test_create_node_defaults(self):
        """Test creating a node with default values."""
        node = ClusterNode(node_id="n1", address="10.0.0.1")
        assert node.node_id == "n1"
        assert node.address == "10.0.0.1"
        assert node.port == DEFAULT_CLUSTER_PORT
        assert node.status == NodeStatus.ONLINE
        assert node.last_heartbeat == ""
        assert node.load == 0

    def test_create_node_custom(self, node_a):
        """Test creating a node with custom values."""
        assert node_a.node_id == "node-a"
        assert node_a.address == "10.0.0.1"
        assert node_a.port == 8444
        assert node_a.status == NodeStatus.ONLINE
        assert node_a.load == 0

    def test_node_to_dict(self, node_a):
        """Test serializing a node to dict."""
        d = node_a.to_dict()
        assert d["node_id"] == "node-a"
        assert d["address"] == "10.0.0.1"
        assert d["port"] == 8444
        assert d["status"] == "online"
        assert d["load"] == 0

    def test_node_from_dict(self, node_a):
        """Test deserializing a node from dict."""
        d = node_a.to_dict()
        node2 = ClusterNode.from_dict(d)
        assert node2.node_id == node_a.node_id
        assert node2.address == node_a.address
        assert node2.port == node_a.port
        assert node2.status == node_a.status
        assert node2.load == node_a.load

    def test_node_from_dict_string_status(self):
        """Test deserializing a node with string status."""
        d = {"node_id": "n1", "address": "10.0.0.1", "status": "draining"}
        node = ClusterNode.from_dict(d)
        assert node.status == NodeStatus.DRAINING

    def test_generate_node_id(self):
        """Test that generate_id produces a stable ID for a process."""
        id1 = ClusterNode.generate_id()
        id2 = ClusterNode.generate_id()
        # Same process = same ID
        assert id1 == id2
        assert id1.startswith("picodome-")

    def test_node_status_enum(self):
        """Test NodeStatus enum values."""
        assert NodeStatus.ONLINE.value == "online"
        assert NodeStatus.OFFLINE.value == "offline"
        assert NodeStatus.DRAINING.value == "draining"

    def test_node_comparison_by_load(self):
        """Test that nodes sort deterministically by (load, node_id)."""
        n1 = ClusterNode(node_id="b", address="10.0.0.1", load=0)
        n2 = ClusterNode(node_id="a", address="10.0.0.2", load=0)
        n3 = ClusterNode(node_id="c", address="10.0.0.3", load=3)
        sorted_nodes = sorted([n1, n2, n3], key=lambda n: (n.load, n.node_id))
        assert sorted_nodes[0].node_id == "a"  # load=0, lowest node_id
        assert sorted_nodes[1].node_id == "b"  # load=0, next node_id
        assert sorted_nodes[2].node_id == "c"  # load=3


# ─── ScanRequest tests ──────────────────────────────────────────────────────


class TestScanRequest:
    """Tests for ScanRequest dataclass."""

    def test_create_scan_request(self, scan_request):
        """Test creating a scan request."""
        assert scan_request.scan_id == "scan-001"
        assert scan_request.command == ["npm", "install", "express"]
        assert scan_request.priority == 0
        assert scan_request.assigned_node is None
        assert scan_request.status == "pending"

    def test_scan_to_dict(self, scan_request):
        """Test serializing a scan request."""
        d = scan_request.to_dict()
        assert d["scan_id"] == "scan-001"
        assert d["command"] == ["npm", "install", "express"]
        assert d["status"] == "pending"

    def test_scan_from_dict(self, scan_request):
        """Test deserializing a scan request."""
        d = scan_request.to_dict()
        scan2 = ScanRequest.from_dict(d)
        assert scan2.scan_id == scan_request.scan_id
        assert scan2.command == scan_request.command
        assert scan2.status == scan_request.status

    def test_scan_round_trip(self):
        """Test that scan serialization round-trips correctly."""
        scan = ScanRequest(
            scan_id="scan-rt",
            command=["python3", "-c", "print('hello')"],
            priority=5,
            assigned_node="node-1",
            created_at="2026-01-01T12:00:00Z",
            status="running",
        )
        d = scan.to_dict()
        restored = ScanRequest.from_dict(d)
        assert restored.scan_id == scan.scan_id
        assert restored.command == scan.command
        assert restored.priority == scan.priority
        assert restored.assigned_node == scan.assigned_node
        assert restored.created_at == scan.created_at
        assert restored.status == scan.status


# ─── State-backend contract tests (memory + sqlite) ─────────────────────────


class TestStateBackends:
    """Common CRUD contract that both MemoryStateBackend and SQLiteStateBackend
    must satisfy. Parametrized over ``any_backend`` so each test runs once per
    backend. The strictest assertion set (the SQLite versions, which check every
    deserialized field) is used — anything that holds for SQLite holds for memory.
    """

    def test_save_and_load_node(self, any_backend, node_a):
        any_backend.save_node(node_a)
        loaded = any_backend.load_node(node_a.node_id)
        assert loaded is not None
        assert loaded.node_id == node_a.node_id
        assert loaded.address == node_a.address
        assert loaded.port == node_a.port
        assert loaded.status == node_a.status
        assert loaded.load == node_a.load

    def test_load_nonexistent_node(self, any_backend):
        assert any_backend.load_node("nonexistent") is None

    def test_load_all_nodes(self, any_backend, node_a, node_b):
        any_backend.save_node(node_a)
        any_backend.save_node(node_b)
        assert len(any_backend.load_all_nodes()) == 2

    def test_delete_node(self, any_backend, node_a):
        any_backend.save_node(node_a)
        any_backend.delete_node(node_a.node_id)
        assert any_backend.load_node(node_a.node_id) is None

    def test_save_and_load_scan(self, any_backend, scan_request):
        any_backend.save_scan(scan_request)
        loaded = any_backend.load_scan(scan_request.scan_id)
        assert loaded is not None
        assert loaded.scan_id == scan_request.scan_id
        assert loaded.command == scan_request.command

    def test_delete_scan(self, any_backend, scan_request):
        any_backend.save_scan(scan_request)
        any_backend.delete_scan(scan_request.scan_id)
        assert any_backend.load_scan(scan_request.scan_id) is None

    def test_leader_id(self, any_backend):
        assert any_backend.get_leader_id() is None
        any_backend.set_leader_id("node-leader")
        assert any_backend.get_leader_id() == "node-leader"

    def test_update_node_overwrites(self, any_backend, node_a):
        any_backend.save_node(node_a)
        node_a.load = 10
        any_backend.save_node(node_a)
        assert any_backend.load_node(node_a.node_id).load == 10


# ─── Backend-specific tests (no common equivalent) ──────────────────────────


class TestMemoryStateBackendExtras:
    """Memory-only: scan listing helpers + thread safety (sqlite has no
    equivalent listing tests and uses WAL for concurrency)."""

    def test_load_nonexistent_scan(self, memory_backend):
        assert memory_backend.load_scan("nonexistent") is None

    def test_load_all_scans(self, memory_backend, scan_request):
        memory_backend.save_scan(scan_request)
        assert len(memory_backend.load_all_scans()) == 1

    def test_thread_safety(self, memory_backend):
        errors = []

        def add_nodes(start, count):
            try:
                for i in range(start, start + count):
                    node = ClusterNode(node_id=f"node-{i}", address=f"10.0.0.{i}")
                    memory_backend.save_node(node)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=add_nodes, args=(0, 50)),
            threading.Thread(target=add_nodes, args=(50, 50)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(memory_backend.load_all_nodes()) == 100


class TestSQLiteStateBackendExtras:
    """SQLite-only: state persists across backend instances (memory cannot)."""

    def test_persistence(self, tmp_path, node_a):
        db_path = tmp_path / "persist_test.db"
        backend1 = SQLiteStateBackend(db_path=db_path)
        backend1.save_node(node_a)
        backend1.set_leader_id("node-a")

        # Reopen the same DB file → state must survive the reopen.
        backend2 = SQLiteStateBackend(db_path=db_path)
        loaded = backend2.load_node(node_a.node_id)
        assert loaded is not None
        assert loaded.node_id == node_a.node_id
        assert backend2.get_leader_id() == "node-a"


# ─── ClusterState tests ──────────────────────────────────────────────────────


class TestClusterState:
    """Tests for ClusterState."""

    def test_add_and_get_node(self, cluster_state, node_a):
        """Test adding and retrieving a node."""
        cluster_state.add_node(node_a)
        loaded = cluster_state.get_node(node_a.node_id)
        assert loaded is not None
        assert loaded.node_id == node_a.node_id

    def test_remove_node(self, cluster_state, node_a):
        """Test removing a node."""
        cluster_state.add_node(node_a)
        cluster_state.remove_node(node_a.node_id)
        assert cluster_state.get_node(node_a.node_id) is None

    def test_list_nodes_all(self, cluster_state, node_a, node_b, node_c):
        """Test listing all nodes."""
        cluster_state.add_node(node_a)
        cluster_state.add_node(node_b)
        cluster_state.add_node(node_c)
        nodes = cluster_state.list_nodes()
        assert len(nodes) == 3
        # Sorted by node_id
        assert nodes[0].node_id == "node-a"
        assert nodes[1].node_id == "node-b"
        assert nodes[2].node_id == "node-c"

    def test_list_nodes_by_status(self, cluster_state, node_a, node_b):
        """Test listing nodes filtered by status."""
        node_b.status = NodeStatus.OFFLINE
        cluster_state.add_node(node_a)
        cluster_state.add_node(node_b)
        online = cluster_state.list_nodes(status=NodeStatus.ONLINE)
        assert len(online) == 1
        assert online[0].node_id == "node-a"

    def test_assign_scan_least_loaded(self, cluster_state, node_a, node_b, node_c, scan_request):
        """Test that scans are assigned to the least-loaded node."""
        cluster_state.add_node(node_a)  # load=0
        cluster_state.add_node(node_b)  # load=2
        cluster_state.add_node(node_c)  # load=5

        cluster_state.add_scan(scan_request)
        assigned = cluster_state.assign_scan(scan_request.scan_id)

        assert assigned is not None
        assert assigned.node_id == "node-a"  # least loaded (load=0)

    def test_assign_scan_deterministic_with_equal_load(self, cluster_state, scan_request):
        """Test that assignment is deterministic when loads are equal."""
        n1 = ClusterNode(node_id="alpha", address="10.0.0.1", load=0)
        n2 = ClusterNode(node_id="beta", address="10.0.0.2", load=0)
        cluster_state.add_node(n1)
        cluster_state.add_node(n2)

        cluster_state.add_scan(scan_request)
        assigned = cluster_state.assign_scan(scan_request.scan_id)
        assert assigned is not None
        assert assigned.node_id == "alpha"  # lowest node_id wins

    def test_assign_scan_no_online_nodes(self, cluster_state, scan_request):
        """Test assigning a scan when no nodes are online."""
        offline = ClusterNode(node_id="offline-1", address="10.0.0.1", status=NodeStatus.OFFLINE)
        cluster_state.add_node(offline)
        cluster_state.add_scan(scan_request)
        assigned = cluster_state.assign_scan(scan_request.scan_id)
        assert assigned is None

    def test_assign_scan_unknown_scan(self, cluster_state, node_a):
        """Test assigning an unknown scan."""
        cluster_state.add_node(node_a)
        assigned = cluster_state.assign_scan("nonexistent-scan")
        assert assigned is None

    def test_complete_scan(self, cluster_state, node_a, scan_request):
        """Test completing a scan decrements node load."""
        cluster_state.add_node(node_a)
        cluster_state.add_scan(scan_request)
        cluster_state.assign_scan(scan_request.scan_id)

        # Node load should be 1 after assignment
        loaded = cluster_state.get_node(node_a.node_id)
        assert loaded.load == 1

        # Complete the scan
        cluster_state.complete_scan(scan_request.scan_id, node_a.node_id)

        # Node load should be 0 after completion
        loaded = cluster_state.get_node(node_a.node_id)
        assert loaded.load == 0

        # Scan status should be completed
        scan = cluster_state.backend.load_scan(scan_request.scan_id)
        assert scan.status == "completed"

    def test_fail_scan(self, cluster_state, node_a, scan_request):
        """Test failing a scan resets it to pending."""
        cluster_state.add_node(node_a)
        cluster_state.add_scan(scan_request)
        cluster_state.assign_scan(scan_request.scan_id)

        # Node load should be 1
        assert cluster_state.get_node(node_a.node_id).load == 1

        # Fail the scan
        cluster_state.fail_scan(scan_request.scan_id)

        # Scan should be back to pending
        scan = cluster_state.backend.load_scan(scan_request.scan_id)
        assert scan.status == "pending"
        assert scan.assigned_node is None

        # Node load should be 0
        assert cluster_state.get_node(node_a.node_id).load == 0

    def test_elect_leader(self, cluster_state, node_a, node_b):
        """Test leader election: lowest node_id wins."""
        cluster_state.add_node(node_a)
        cluster_state.add_node(node_b)

        leader_id = cluster_state.elect_leader()
        assert leader_id == "node-a"  # lowest node_id

    def test_elect_leader_no_nodes(self, cluster_state):
        """Test leader election with no nodes."""
        leader_id = cluster_state.elect_leader()
        assert leader_id is None

    def test_get_pending_scans(self, cluster_state, node_a):
        """Test getting pending scans."""
        s1 = ScanRequest(scan_id="s1", command=["echo", "1"])
        s2 = ScanRequest(scan_id="s2", command=["echo", "2"])
        cluster_state.add_node(node_a)
        cluster_state.add_scan(s1)
        cluster_state.add_scan(s2)

        pending = cluster_state.get_pending_scans()
        assert len(pending) == 2

    def test_get_scans_for_node(self, cluster_state, node_a, scan_request):
        """Test getting scans assigned to a specific node."""
        cluster_state.add_node(node_a)
        cluster_state.add_scan(scan_request)
        cluster_state.assign_scan(scan_request.scan_id)

        scans = cluster_state.get_scans_for_node(node_a.node_id)
        assert len(scans) == 1
        assert scans[0].scan_id == scan_request.scan_id

    def test_state_snapshot(self, cluster_state, node_a, scan_request):
        """Test getting a state snapshot."""
        cluster_state.add_node(node_a)
        cluster_state.add_scan(scan_request)

        snapshot = cluster_state.get_state_snapshot()
        assert "nodes" in snapshot
        assert "scans" in snapshot
        assert "leader_id" in snapshot
        assert "timestamp" in snapshot
        assert len(snapshot["nodes"]) == 1
        assert len(snapshot["scans"]) == 1

    def test_merge_state(self, cluster_state):
        """Test merging state from a peer."""
        snapshot = {
            "nodes": [
                {
                    "node_id": "remote-1",
                    "address": "10.0.0.10",
                    "port": 8444,
                    "status": "online",
                    "last_heartbeat": "2026-01-01T12:00:00Z",
                    "load": 3,
                },
            ],
            "scans": [
                {
                    "scan_id": "remote-scan-1",
                    "command": ["echo", "remote"],
                    "priority": 0,
                    "assigned_node": None,
                    "created_at": "",
                    "status": "pending",
                },
            ],
            "leader_id": "remote-1",
        }

        cluster_state.merge_state(snapshot)

        # Remote node should be added
        node = cluster_state.get_node("remote-1")
        assert node is not None
        assert node.address == "10.0.0.10"

        # Leader should be set
        assert cluster_state.get_leader_id() == "remote-1"

    def test_merge_state_keeps_newer_heartbeat(self, cluster_state, node_a):
        """Test that merge keeps the node with newer heartbeat."""
        cluster_state.add_node(node_a)  # heartbeat="2026-01-01T00:00:00Z"

        snapshot = {
            "nodes": [
                {
                    "node_id": "node-a",
                    "address": "10.0.0.1",
                    "port": 8444,
                    "status": "online",
                    "last_heartbeat": "2026-01-02T00:00:00Z",
                    "load": 0,
                },
            ],
            "scans": [],
            "leader_id": None,
        }

        cluster_state.merge_state(snapshot)

        # Remote node has newer heartbeat, so it should win
        node = cluster_state.get_node("node-a")
        assert node.last_heartbeat == "2026-01-02T00:00:00Z"

    def test_update_node(self, cluster_state, node_a):
        """Test updating a node's state."""
        cluster_state.add_node(node_a)
        node_a.load = 5
        node_a.status = NodeStatus.DRAINING
        cluster_state.update_node(node_a)

        loaded = cluster_state.get_node(node_a.node_id)
        assert loaded.load == 5
        assert loaded.status == NodeStatus.DRAINING


# ─── ClusterManager tests ───────────────────────────────────────────────────


class TestClusterManager:
    """Tests for ClusterManager."""

    def test_start_registers_self(self, started_manager):
        node = started_manager.state.get_node("test-node")
        assert node is not None
        assert node.status == NodeStatus.ONLINE
        assert node.address == "127.0.0.1"

    def test_start_elects_self_leader(self, started_manager):
        assert started_manager.state.get_leader_id() == "test-node"

    def test_stop_deregisters(self, manager):
        manager.start()
        manager.stop()
        assert manager.state.get_node("test-node") is None

    def test_assign_scan(self, started_manager, scan_request):
        assigned = started_manager.assign_scan(scan_request)
        assert assigned is not None
        assert assigned.node_id == "test-node"

    def test_assign_scan_no_nodes(self, memory_backend):
        # Don't start the manager — no nodes registered
        mgr = ClusterManager(
            address="127.0.0.1",
            node_id="test-node",
            backend=memory_backend,
            heartbeat_interval=999,
            heartbeat_timeout=999,
        )
        scan = ScanRequest(scan_id="s1", command=["echo", "test"])
        mgr.assign_scan(scan)
        # No online nodes, so assignment should fail, but the scan is still added to state.
        assert mgr.state.backend.load_scan("s1") is not None

    def test_handle_heartbeat(self, started_manager):
        peer = ClusterNode(node_id="peer-1", address="10.0.0.2", status=NodeStatus.ONLINE)
        started_manager.state.add_node(peer)

        updated = started_manager.handle_heartbeat("peer-1", status="online", load=3)
        assert updated is not None
        assert updated.load == 3
        assert updated.status == NodeStatus.ONLINE
        assert updated.last_heartbeat != ""

    def test_handle_heartbeat_unknown_node(self, manager):
        assert manager.handle_heartbeat("unknown-node", status="online", load=0) is None

    def test_handle_node_failure(self, started_manager, node_b):
        started_manager.state.add_node(node_b)  # node-b with load=2
        s1 = ScanRequest(scan_id="s1", command=["echo", "1"], assigned_node="node-b", status="running")
        s2 = ScanRequest(scan_id="s2", command=["echo", "2"], assigned_node="node-b", status="running")
        started_manager.state.add_scan(s1)
        started_manager.state.add_scan(s2)

        redistributed = started_manager.handle_node_failure("node-b")
        assert len(redistributed) == 2
        assert started_manager.state.get_node("node-b").status == NodeStatus.OFFLINE
        # Scans should be reassigned to another node and still running.
        assert started_manager.state.backend.load_scan("s1").status == "running"

    def test_handle_node_failure_no_scans(self, started_manager, node_b):
        started_manager.state.add_node(node_b)
        redistributed = started_manager.handle_node_failure("node-b")
        assert len(redistributed) == 0
        assert started_manager.state.get_node("node-b").status == NodeStatus.OFFLINE

    def test_get_status(self, started_manager, node_b):
        started_manager.state.add_node(node_b)
        status = started_manager.get_status()

        assert status["self_id"] == "test-node"
        assert status["leader_id"] == "test-node"
        assert status["nodes_total"] == 2  # self + node_b
        assert status["nodes_online"] == 2
        assert "nodes" in status
        assert "scans_total" in status

    def test_sync_state(self, started_manager, node_b):
        started_manager.state.add_node(node_b)
        snapshot = started_manager.sync_state()

        assert "nodes" in snapshot
        assert "scans" in snapshot
        assert "leader_id" in snapshot
        assert "timestamp" in snapshot
        assert len(snapshot["nodes"]) >= 1

    def test_merge_peer_state(self, started_manager):
        snapshot = {
            "nodes": [
                {
                    "node_id": "peer-1",
                    "address": "10.0.0.5",
                    "port": 8444,
                    "status": "online",
                    "last_heartbeat": "2026-01-01T12:00:00Z",
                    "load": 0,
                },
            ],
            "scans": [],
            "leader_id": "peer-1",
        }
        started_manager.merge_peer_state(snapshot)

        peer = started_manager.state.get_node("peer-1")
        assert peer is not None
        assert peer.address == "10.0.0.5"

    def test_is_running_flag(self, manager):
        assert not manager.is_running
        manager.start()
        assert manager.is_running
        manager.stop()
        assert not manager.is_running

    def test_start_idempotent(self, manager):
        manager.start()
        manager.start()  # Should not raise
        manager.stop()


# ─── Utility function tests ─────────────────────────────────────────────────


class TestUtilities:
    """Tests for the _parse_iso_timestamp helper."""

    @pytest.mark.parametrize(
        "value,expect_not_none",
        [
            ("2026-01-01T00:00:00Z", True),
            ("2026-01-01T00:00:00+00:00", True),
            ("not-a-timestamp", False),
            ("", False),
        ],
    )
    def test_parse_iso_timestamp(self, value, expect_not_none):
        ts = _parse_iso_timestamp(value)
        if expect_not_none:
            assert ts is not None
            assert isinstance(ts, float)
        else:
            assert ts is None


# ─── Integration tests ──────────────────────────────────────────────────────


class TestClusterIntegration:
    """Integration tests for full cluster workflows."""

    def test_full_cluster_lifecycle(self, memory_backend):
        """Test a complete cluster lifecycle: start, assign scans, stop."""
        manager = ClusterManager(
            address="127.0.0.1",
            node_id="lifecycle-node",
            backend=memory_backend,
            heartbeat_interval=999,
            heartbeat_timeout=999,
        )

        # Start
        manager.start()
        assert manager.is_running

        # Assign a scan
        scan = ScanRequest(scan_id="lifecycle-scan", command=["echo", "test"])
        node = manager.assign_scan(scan)
        assert node is not None
        assert node.node_id == "lifecycle-node"

        # Status
        status = manager.get_status()
        assert status["nodes_online"] == 1
        assert status["scans_total"] == 1

        # Stop
        manager.stop()
        assert not manager.is_running

    def test_multi_node_scan_distribution(self, memory_backend):
        """Test that scans are distributed across multiple nodes."""
        state = ClusterState(backend=memory_backend)

        # Create 3 nodes with different loads
        n1 = ClusterNode(node_id="n1", address="10.0.0.1", load=0)
        n2 = ClusterNode(node_id="n2", address="10.0.0.2", load=2)
        n3 = ClusterNode(node_id="n3", address="10.0.0.3", load=5)
        state.add_node(n1)
        state.add_node(n2)
        state.add_node(n3)

        # First scan goes to n1 (least loaded)
        s1 = ScanRequest(scan_id="s1", command=["echo", "1"])
        state.add_scan(s1)
        assigned = state.assign_scan("s1")
        assert assigned.node_id == "n1"

        # n1 load is now 1, so second scan still goes to n1 (load=1 < load=2)
        s2 = ScanRequest(scan_id="s2", command=["echo", "2"])
        state.add_scan(s2)
        assigned = state.assign_scan("s2")
        assert assigned.node_id == "n1"

        # n1 load is now 2, so third scan: n1=2, n2=2, n3=5 → n1 (lowest id)
        s3 = ScanRequest(scan_id="s3", command=["echo", "3"])
        state.add_scan(s3)
        assigned = state.assign_scan("s3")
        assert assigned.node_id == "n1"

    def test_node_failure_redistribution(self, memory_backend):
        """Test that scans are redistributed when a node fails."""
        state = ClusterState(backend=memory_backend)

        # Create 2 nodes
        n1 = ClusterNode(node_id="survivor", address="10.0.0.1", load=0)
        n2 = ClusterNode(node_id="failing", address="10.0.0.2", load=1)
        state.add_node(n1)
        state.add_node(n2)

        # Create a scan assigned to failing node
        s1 = ScanRequest(scan_id="s1", command=["echo", "1"], assigned_node="failing", status="running")
        state.add_scan(s1)

        # Fail the node
        n2.status = NodeStatus.OFFLINE
        state.update_node(n2)

        # Fail and reassign the scan
        state.fail_scan("s1")
        assigned = state.assign_scan("s1")
        assert assigned is not None
        assert assigned.node_id == "survivor"

    def test_sqlite_backend_full_workflow(self, tmp_path):
        """Test full cluster workflow with SQLite backend."""
        db_path = tmp_path / "workflow.db"
        backend = SQLiteStateBackend(db_path=db_path)
        state = ClusterState(backend=backend)

        # Add nodes
        n1 = ClusterNode(node_id="sqlite-n1", address="10.0.0.1", load=0)
        n2 = ClusterNode(node_id="sqlite-n2", address="10.0.0.2", load=3)
        state.add_node(n1)
        state.add_node(n2)

        # Assign scan
        s1 = ScanRequest(scan_id="sqlite-s1", command=["echo", "sqlite"])
        state.add_scan(s1)
        assigned = state.assign_scan("sqlite-s1")
        assert assigned.node_id == "sqlite-n1"  # least loaded

        # Complete scan
        state.complete_scan("sqlite-s1", "sqlite-n1")
        node = state.get_node("sqlite-n1")
        assert node.load == 0

        # Verify persistence
        backend2 = SQLiteStateBackend(db_path=db_path)
        state2 = ClusterState(backend=backend2)
        nodes = state2.list_nodes()
        assert len(nodes) == 2

    def test_singleton_cluster_manager(self):
        """Test module-level singleton functions."""
        # Reset singleton
        import picosentry.sandbox.cluster.manager as mgr_mod

        mgr_mod._cluster_manager = None

        mgr1 = get_cluster_manager()
        mgr2 = get_cluster_manager()
        assert mgr1 is mgr2

        # Setup should create a new one
        mgr3 = setup_cluster_manager(address="10.0.0.1", node_id="custom-node")
        assert mgr3.node_id == "custom-node"

        # Cleanup
        mgr_mod._cluster_manager = None


# ─── Multi-node gossip tests ─────────────────────────────────────────────────


class TestGossipMerge:
    """Tests for multi-node gossip via get_state_snapshot() / merge_state().

    These exercise the gossip primitives that let cluster nodes exchange
    state without a central coordinator.  Each node runs its own
    ClusterState and periodically exchanges snapshots with peers.
    """

    def test_snapshot_round_trip(self, cluster_state, node_a, node_b):
        """A snapshot from one node should be mergeable into another."""
        cluster_state.add_node(node_a)
        cluster_state.add_node(node_b)
        cluster_state.elect_leader()

        snap = cluster_state.get_state_snapshot()
        assert "nodes" in snap
        assert "scans" in snap
        assert "leader_id" in snap
        assert snap["leader_id"] == "node-a"  # lowest node_id wins

        # Merge into a fresh state
        state2 = ClusterState()
        state2.merge_state(snap)
        assert len(state2.list_nodes()) == 2
        assert state2.get_leader_id() == "node-a"

    def test_last_writer_wins_nodes(self):
        """When two nodes report different heartbeats for the same node,
        the fresher heartbeat wins (last-writer-wins)."""
        state_a = ClusterState()
        state_b = ClusterState()

        # Node A reports node-x with an old heartbeat
        old_node = ClusterNode(
            node_id="node-x",
            address="10.0.0.1",
            last_heartbeat="2026-06-13T00:00:00Z",
            load=0,
        )
        state_a.add_node(old_node)

        # Node B reports the same node with a newer heartbeat + higher load
        new_node = ClusterNode(
            node_id="node-x",
            address="10.0.0.1",
            last_heartbeat="2026-06-13T12:00:00Z",
            load=5,
        )
        state_b.add_node(new_node)

        # Merge B's snapshot into A
        snap_b = state_b.get_state_snapshot()
        state_a.merge_state(snap_b)

        merged = state_a.get_node("node-x")
        assert merged is not None
        assert merged.last_heartbeat == "2026-06-13T12:00:00Z"  # newer wins
        assert merged.load == 5  # from the newer report

    def test_scan_status_priority_merge(self):
        """When two nodes report different statuses for the same scan,
        the higher-priority status wins (completed > running > pending > failed)."""
        state_a = ClusterState()
        state_b = ClusterState()

        scan = ScanRequest(scan_id="s1", command=["echo", "hi"], status="pending")
        state_a.add_scan(scan)

        # Node B completed the scan
        scan_completed = ScanRequest(
            scan_id="s1",
            command=["echo", "hi"],
            status="completed",
            assigned_node="node-b",
        )
        state_b.add_scan(scan_completed)

        # Merge B into A — completed should win over pending
        snap_b = state_b.get_state_snapshot()
        state_a.merge_state(snap_b)

        merged_scans = [s for s in state_a._backend.load_all_scans() if s.scan_id == "s1"]
        assert len(merged_scans) == 1
        assert merged_scans[0].status == "completed"

    def test_new_node_discovered_via_gossip(self):
        """A node should learn about peers it hasn't directly seen
        by merging another peer's snapshot."""
        state_a = ClusterState()
        state_b = ClusterState()

        # Node A only knows about itself
        n1 = ClusterNode(node_id="node-a", address="10.0.0.1")
        state_a.add_node(n1)

        # Node B knows about itself AND node-c
        n2 = ClusterNode(node_id="node-b", address="10.0.0.2")
        n3 = ClusterNode(node_id="node-c", address="10.0.0.3")
        state_b.add_node(n2)
        state_b.add_node(n3)

        # A merges B's snapshot — should discover node-c
        snap_b = state_b.get_state_snapshot()
        state_a.merge_state(snap_b)

        nodes = state_a.list_nodes()
        assert len(nodes) == 3  # node-a, node-b, node-c
        assert any(n.node_id == "node-c" for n in nodes)

    def test_leader_election_consensus(self):
        """After merging snapshots from multiple peers, all nodes
        should agree on the same leader (lowest online node_id)."""
        state_a = ClusterState()
        state_b = ClusterState()
        state_c = ClusterState()

        # Each node knows a different subset
        n1 = ClusterNode(node_id="node-a", address="10.0.0.1")
        n2 = ClusterNode(node_id="node-b", address="10.0.0.2")
        n3 = ClusterNode(node_id="node-c", address="10.0.0.3")

        state_a.add_node(n1)
        state_b.add_node(n1)
        state_b.add_node(n2)
        state_c.add_node(n2)
        state_c.add_node(n3)

        # All elect independently
        state_a.elect_leader()
        state_b.elect_leader()
        state_c.elect_leader()

        # After full mesh merge, all should agree on node-a (lowest id)
        snap_a = state_a.get_state_snapshot()
        snap_b = state_b.get_state_snapshot()
        snap_c = state_c.get_state_snapshot()

        state_a.merge_state(snap_b)
        state_a.merge_state(snap_c)
        state_b.merge_state(snap_a)
        state_b.merge_state(snap_c)
        state_c.merge_state(snap_a)
        state_c.merge_state(snap_b)

        assert state_a.get_leader_id() == "node-a"
        assert state_b.get_leader_id() == "node-a"
        assert state_c.get_leader_id() == "node-a"

    def test_offline_node_removed_via_gossip(self):
        """When a peer reports a node as OFFLINE with a newer heartbeat,
        the receiving node should mark it OFFLINE (last-writer-wins)."""
        state_a = ClusterState()
        state_b = ClusterState()

        # Both know about node-x as ONLINE
        nx = ClusterNode(
            node_id="node-x",
            address="10.0.0.99",
            status=NodeStatus.ONLINE,
            last_heartbeat="2026-06-13T00:00:00Z",
        )
        state_a.add_node(nx)
        state_b.add_node(nx)

        # Node B detects node-x is down (newer heartbeat, OFFLINE)
        nx_offline = ClusterNode(
            node_id="node-x",
            address="10.0.0.99",
            status=NodeStatus.OFFLINE,
            last_heartbeat="2026-06-13T12:00:00Z",
        )
        state_b.update_node(nx_offline)

        # A merges B's snapshot — should mark node-x OFFLINE
        snap_b = state_b.get_state_snapshot()
        state_a.merge_state(snap_b)

        merged = state_a.get_node("node-x")
        assert merged is not None
        assert merged.status == NodeStatus.OFFLINE

    def test_gossip_with_sqlite_backend(self, tmp_path):
        """Gossip merge should work identically with SQLite backend."""
        db_a = tmp_path / "gossip_a.db"
        db_b = tmp_path / "gossip_b.db"

        state_a = ClusterState(backend=SQLiteStateBackend(db_path=db_a))
        state_b = ClusterState(backend=SQLiteStateBackend(db_path=db_b))

        n1 = ClusterNode(node_id="sqlite-g1", address="10.0.0.1", load=0)
        n2 = ClusterNode(node_id="sqlite-g2", address="10.0.0.2", load=2)
        state_a.add_node(n1)
        state_b.add_node(n1)
        state_b.add_node(n2)

        s1 = ScanRequest(scan_id="gs1", command=["echo", "gossip"], status="completed")
        state_b.add_scan(s1)

        # A merges B's snapshot
        snap_b = state_b.get_state_snapshot()
        state_a.merge_state(snap_b)

        assert len(state_a.list_nodes()) == 2
        scans = state_a._backend.load_all_scans()
        assert any(s.scan_id == "gs1" and s.status == "completed" for s in scans)


# ─── Gossip loop tests ──────────────────────────────────────────────────────


class TestGossipLoop:
    """Tests for the periodic gossip loop that exchanges state via HTTP."""

    def test_fetch_and_merge_adds_new_nodes(self, monkeypatch):
        """_fetch_and_merge_peer should add a peer's nodes to local state."""
        mgr = _orchestrator_manager()

        peer_snapshot = {
            "nodes": [
                {
                    "node_id": "peer-a",
                    "address": "10.0.0.2",
                    "port": 8443,
                    "status": "online",
                    "last_heartbeat": "2026-06-13T12:00:00Z",
                    "load": 0,
                },
                {
                    "node_id": "peer-b",
                    "address": "10.0.0.3",
                    "port": 8443,
                    "status": "online",
                    "last_heartbeat": "2026-06-13T12:00:00Z",
                    "load": 2,
                },
            ],
            "scans": [],
            "leader_id": "peer-a",
        }
        _mock_urlopen(monkeypatch, json.dumps(peer_snapshot).encode())

        mgr._fetch_and_merge_peer(ClusterNode(node_id="peer-a", address="10.0.0.2", port=8443))

        nodes = mgr.state.list_nodes()
        assert len(nodes) == 3  # self + peer-a + peer-b
        assert any(n.node_id == "peer-b" for n in nodes)
        assert mgr.state.get_leader_id() == "peer-a"

    def test_fetch_and_merge_skips_invalid_response(self, monkeypatch):
        """Non-dict responses should be silently skipped."""
        mgr = _orchestrator_manager()
        _mock_urlopen(monkeypatch, b'"not a dict"')

        mgr._fetch_and_merge_peer(ClusterNode(node_id="peer-x", address="10.0.0.99", port=8443))

        # Should still only have self-node (invalid response skipped)
        assert len(mgr.state.list_nodes()) == 1

    def test_gossip_loop_stops_with_manager(self):
        """The gossip thread should exit when the manager stops."""
        # heartbeat_interval is needed here so __init__ sets up _stop_event;
        # we don't call start() so no heartbeat thread is spawned.
        mgr = _orchestrator_manager(node_id="test-node", heartbeat_interval=1)
        mgr._gossip_thread = threading.Thread(
            target=mgr._gossip_loop,
            daemon=True,
            name="test-gossip",
        )
        mgr._gossip_thread.start()
        assert mgr._gossip_thread.is_alive()

        # Stop should terminate the thread.
        mgr._running = False
        mgr._stop_event.set()
        mgr._gossip_thread.join(timeout=5.0)
        assert not mgr._gossip_thread.is_alive()


class TestClusterBetaWarnings:
    """Cluster/gossip features must advertise their beta status."""

    def test_setup_cluster_manager_logs_beta_warning(self, caplog):
        with caplog.at_level(logging.WARNING, logger="picodome.cluster"):
            setup_cluster_manager(node_id="warn-node", cluster_token="test-token")

        assert any("BETA" in r.message for r in caplog.records)

    def test_cluster_manager_start_logs_beta_warning(self, caplog):
        mgr = ClusterManager(node_id="warn-start-node")
        with caplog.at_level(logging.WARNING, logger="picodome.cluster"):
            mgr.start()
            mgr.stop()

        assert any("BETA" in r.message for r in caplog.records)

    def test_assign_scan_logs_beta_warning(self, cluster_state, node_a, scan_request, caplog):
        cluster_state.add_node(node_a)
        mgr = ClusterManager(backend=cluster_state._backend, node_id="warn-scan-node")
        # manager.start() would spawn threads; just wire state directly.
        mgr._state = cluster_state

        with caplog.at_level(logging.WARNING, logger="picodome.cluster"):
            mgr.assign_scan(scan_request)

        assert any("BETA" in r.message for r in caplog.records)


class _BoomAudit:
    """Stub audit logger whose ``record`` always raises — used to verify the
    cluster manager logs (rather than swallows) audit-failure exceptions."""

    def record(self, **_kwargs):
        raise RuntimeError("audit disk full")


def _orchestrator_manager(node_id="self-node", port=8443, heartbeat_interval=None):
    """Build a ClusterManager with a registered self-node, ready for gossip tests.

    ``picosentry.sandbox.cluster.manager.ClusterManager`` is a re-export of
    ``orchestrator.ClusterManager`` (manager.py imports it), so this is the
    same class the gossip tests need — no separate import required.
    """
    kwargs = {"address": "127.0.0.1", "port": port, "node_id": node_id}
    if heartbeat_interval is not None:
        kwargs["heartbeat_interval"] = heartbeat_interval
    mgr = ClusterManager(**kwargs)
    mgr._running = True
    mgr._state.add_node(ClusterNode(node_id=node_id, address="127.0.0.1", port=port))
    return mgr


def _mock_urlopen(monkeypatch, body_bytes):
    """Patch urllib.request.urlopen to return ``body_bytes`` from read()."""

    class _Resp:
        def read(self, n=-1):
            return body_bytes[:n] if n is not None and n >= 0 else body_bytes

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda _req, timeout=None: _Resp())


def _state_with_token(token):
    """Build a fresh ClusterState backed by MemoryStateBackend with ``token``
    as its cluster_token. Used by the token-rotation tests."""
    return ClusterState(backend=MemoryStateBackend(), cluster_token=token)


class TestClusterManagerAuditHardening:
    """Cluster manager must log audit failures instead of swallowing them."""

    def test_start_audit_failure_is_logged(self, manager, caplog, monkeypatch):
        with caplog.at_level(logging.WARNING, logger="picodome.cluster"):
            monkeypatch.setattr("picosentry.sandbox.cluster.orchestrator.get_audit_logger", lambda: _BoomAudit())
            manager.start()
            try:
                assert any("Audit record failed" in r.message for r in caplog.records)
            finally:
                monkeypatch.undo()
                manager.stop()

    def test_assign_scan_audit_failure_is_logged(self, manager, caplog, monkeypatch):
        manager.start()
        try:
            with caplog.at_level(logging.WARNING, logger="picodome.cluster"):
                monkeypatch.setattr("picosentry.sandbox.cluster.orchestrator.get_audit_logger", lambda: _BoomAudit())
                request = ScanRequest(scan_id="scan-1", command=["echo", "hi"])
                manager.assign_scan(request)

            assert any("Audit record failed" in r.message for r in caplog.records)
        finally:
            monkeypatch.undo()
            manager.stop()


class TestClusterTokenRotation:
    """Cluster token rotation and multi-token acceptance."""

    def test_initial_token_is_primary_and_accepted(self):
        state = ClusterState(cluster_token="secret")
        assert state.cluster_token == "secret"
        assert state.token_store.is_accepted("secret")

    def test_rotate_token_keeps_old_accepted(self):
        state = _state_with_token("old-secret")
        state.token_store.rotate("new-secret")

        assert state.cluster_token == "new-secret"
        assert state.token_store.is_accepted("old-secret")
        assert state.token_store.is_accepted("new-secret")

    def test_merge_adopts_remote_token_when_common_token_exists(self):
        local = _state_with_token("shared")
        remote = _state_with_token("shared")
        remote.token_store.rotate("new-secret")

        local.merge_state(remote.get_state_snapshot())
        assert local.token_store.is_accepted("new-secret")

    def test_merge_rejects_remote_with_no_common_token(self):
        local = _state_with_token("secret-a")
        remote = _state_with_token("secret-b")

        with pytest.raises(ValueError, match="cluster token mismatch"):
            local.merge_state(remote.get_state_snapshot())

    def test_cluster_manager_rotate_token(self, started_manager):
        started_manager.state.set_cluster_token("token-v1")
        result = started_manager.rotate_token("token-v2")

        assert result["token_version"] == 2
        assert started_manager.state.cluster_token == "token-v2"
        assert started_manager.state.token_store.is_accepted("token-v1")

    def test_retire_stale_tokens_keeps_primary(self, started_manager):
        started_manager.state.set_cluster_token("token-v1")
        started_manager.rotate_token("token-v2")
        time.sleep(0.1)
        retired = started_manager.retire_stale_tokens(max_age_seconds=0.05)
        assert retired == 1
        assert started_manager.state.token_store.is_accepted("token-v2")
        assert not started_manager.state.token_store.is_accepted("token-v1")
