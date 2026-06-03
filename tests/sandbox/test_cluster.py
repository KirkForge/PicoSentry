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

import threading

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


@pytest.fixture
def cluster_state_sqlite(sqlite_backend):
    """ClusterState with SQLite backend."""
    return ClusterState(backend=sqlite_backend)


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


# ─── MemoryStateBackend tests ───────────────────────────────────────────────


class TestMemoryStateBackend:
    """Tests for MemoryStateBackend."""

    def test_save_and_load_node(self, memory_backend, node_a):
        """Test saving and loading a node."""
        memory_backend.save_node(node_a)
        loaded = memory_backend.load_node(node_a.node_id)
        assert loaded is not None
        assert loaded.node_id == node_a.node_id
        assert loaded.address == node_a.address

    def test_load_nonexistent_node(self, memory_backend):
        """Test loading a node that doesn't exist."""
        assert memory_backend.load_node("nonexistent") is None

    def test_load_all_nodes(self, memory_backend, node_a, node_b):
        """Test loading all nodes."""
        memory_backend.save_node(node_a)
        memory_backend.save_node(node_b)
        nodes = memory_backend.load_all_nodes()
        assert len(nodes) == 2

    def test_delete_node(self, memory_backend, node_a):
        """Test deleting a node."""
        memory_backend.save_node(node_a)
        memory_backend.delete_node(node_a.node_id)
        assert memory_backend.load_node(node_a.node_id) is None

    def test_save_and_load_scan(self, memory_backend, scan_request):
        """Test saving and loading a scan."""
        memory_backend.save_scan(scan_request)
        loaded = memory_backend.load_scan(scan_request.scan_id)
        assert loaded is not None
        assert loaded.scan_id == scan_request.scan_id

    def test_load_nonexistent_scan(self, memory_backend):
        """Test loading a scan that doesn't exist."""
        assert memory_backend.load_scan("nonexistent") is None

    def test_load_all_scans(self, memory_backend, scan_request):
        """Test loading all scans."""
        memory_backend.save_scan(scan_request)
        scans = memory_backend.load_all_scans()
        assert len(scans) == 1

    def test_delete_scan(self, memory_backend, scan_request):
        """Test deleting a scan."""
        memory_backend.save_scan(scan_request)
        memory_backend.delete_scan(scan_request.scan_id)
        assert memory_backend.load_scan(scan_request.scan_id) is None

    def test_leader_id(self, memory_backend):
        """Test leader ID persistence."""
        assert memory_backend.get_leader_id() is None
        memory_backend.set_leader_id("node-leader")
        assert memory_backend.get_leader_id() == "node-leader"

    def test_update_node(self, memory_backend, node_a):
        """Test updating a node (save overwrites)."""
        memory_backend.save_node(node_a)
        node_a.load = 5
        memory_backend.save_node(node_a)
        loaded = memory_backend.load_node(node_a.node_id)
        assert loaded.load == 5

    def test_thread_safety(self, memory_backend):
        """Test concurrent access to memory backend."""
        errors = []

        def add_nodes(start, count):
            try:
                for i in range(start, start + count):
                    node = ClusterNode(
                        node_id=f"node-{i}",
                        address=f"10.0.0.{i}",
                    )
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


# ─── SQLiteStateBackend tests ───────────────────────────────────────────────


class TestSQLiteStateBackend:
    """Tests for SQLiteStateBackend."""

    def test_save_and_load_node(self, sqlite_backend, node_a):
        """Test saving and loading a node in SQLite."""
        sqlite_backend.save_node(node_a)
        loaded = sqlite_backend.load_node(node_a.node_id)
        assert loaded is not None
        assert loaded.node_id == node_a.node_id
        assert loaded.address == node_a.address
        assert loaded.port == node_a.port
        assert loaded.status == node_a.status
        assert loaded.load == node_a.load

    def test_load_nonexistent_node(self, sqlite_backend):
        """Test loading a nonexistent node from SQLite."""
        assert sqlite_backend.load_node("nonexistent") is None

    def test_load_all_nodes(self, sqlite_backend, node_a, node_b):
        """Test loading all nodes from SQLite."""
        sqlite_backend.save_node(node_a)
        sqlite_backend.save_node(node_b)
        nodes = sqlite_backend.load_all_nodes()
        assert len(nodes) == 2

    def test_delete_node(self, sqlite_backend, node_a):
        """Test deleting a node from SQLite."""
        sqlite_backend.save_node(node_a)
        sqlite_backend.delete_node(node_a.node_id)
        assert sqlite_backend.load_node(node_a.node_id) is None

    def test_save_and_load_scan(self, sqlite_backend, scan_request):
        """Test saving and loading a scan in SQLite."""
        sqlite_backend.save_scan(scan_request)
        loaded = sqlite_backend.load_scan(scan_request.scan_id)
        assert loaded is not None
        assert loaded.scan_id == scan_request.scan_id
        assert loaded.command == scan_request.command

    def test_delete_scan(self, sqlite_backend, scan_request):
        """Test deleting a scan from SQLite."""
        sqlite_backend.save_scan(scan_request)
        sqlite_backend.delete_scan(scan_request.scan_id)
        assert sqlite_backend.load_scan(scan_request.scan_id) is None

    def test_leader_id(self, sqlite_backend):
        """Test leader ID in SQLite."""
        assert sqlite_backend.get_leader_id() is None
        sqlite_backend.set_leader_id("node-leader")
        assert sqlite_backend.get_leader_id() == "node-leader"

    def test_persistence(self, tmp_path, node_a):
        """Test that SQLite state persists across backend instances."""
        db_path = tmp_path / "persist_test.db"
        backend1 = SQLiteStateBackend(db_path=db_path)
        backend1.save_node(node_a)
        backend1.set_leader_id("node-a")

        # Create new backend instance with same DB
        backend2 = SQLiteStateBackend(db_path=db_path)
        loaded = backend2.load_node(node_a.node_id)
        assert loaded is not None
        assert loaded.node_id == node_a.node_id
        assert backend2.get_leader_id() == "node-a"

    def test_update_node_overwrites(self, sqlite_backend, node_a):
        """Test that saving a node twice overwrites."""
        sqlite_backend.save_node(node_a)
        node_a.load = 10
        sqlite_backend.save_node(node_a)
        loaded = sqlite_backend.load_node(node_a.node_id)
        assert loaded.load == 10


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

    def test_start_registers_self(self, manager):
        """Test that start() registers the node."""
        manager.start()
        try:
            node = manager.state.get_node("test-node")
            assert node is not None
            assert node.status == NodeStatus.ONLINE
            assert node.address == "127.0.0.1"
        finally:
            manager.stop()

    def test_start_elects_self_leader(self, manager):
        """Test that the first node becomes leader."""
        manager.start()
        try:
            leader_id = manager.state.get_leader_id()
            assert leader_id == "test-node"
        finally:
            manager.stop()

    def test_stop_deregisters(self, manager):
        """Test that stop() removes the node from the cluster."""
        manager.start()
        manager.stop()
        node = manager.state.get_node("test-node")
        assert node is None

    def test_assign_scan(self, manager, scan_request):
        """Test assigning a scan through the manager."""
        manager.start()
        try:
            assigned = manager.assign_scan(scan_request)
            assert assigned is not None
            assert assigned.node_id == "test-node"
        finally:
            manager.stop()

    def test_assign_scan_no_nodes(self, memory_backend):
        """Test assigning a scan when no nodes are online."""
        mgr = ClusterManager(
            address="127.0.0.1",
            node_id="test-node",
            backend=memory_backend,
            heartbeat_interval=999,  # Don't start heartbeat threads
            heartbeat_timeout=999,
        )
        # Don't start the manager — no nodes registered
        scan = ScanRequest(scan_id="s1", command=["echo", "test"])
        mgr.assign_scan(scan)
        # No online nodes, so assignment should fail
        # But the scan was added to state
        assert mgr.state.backend.load_scan("s1") is not None

    def test_handle_heartbeat(self, manager):
        """Test processing a heartbeat from a peer."""
        manager.start()
        try:
            # Register a peer node
            peer = ClusterNode(node_id="peer-1", address="10.0.0.2", status=NodeStatus.ONLINE)
            manager.state.add_node(peer)

            # Process heartbeat
            updated = manager.handle_heartbeat("peer-1", status="online", load=3)
            assert updated is not None
            assert updated.load == 3
            assert updated.status == NodeStatus.ONLINE
            assert updated.last_heartbeat != ""
        finally:
            manager.stop()

    def test_handle_heartbeat_unknown_node(self, manager):
        """Test heartbeat from an unknown node."""
        result = manager.handle_heartbeat("unknown-node", status="online", load=0)
        assert result is None

    def test_handle_node_failure(self, manager, node_b):
        """Test handling a node failure redistributes scans."""
        manager.start()
        try:
            # Register self and peer
            manager.state.add_node(node_b)  # node-b with load=2

            # Create scans assigned to node-b
            s1 = ScanRequest(scan_id="s1", command=["echo", "1"], assigned_node="node-b", status="running")
            s2 = ScanRequest(scan_id="s2", command=["echo", "2"], assigned_node="node-b", status="running")
            manager.state.add_scan(s1)
            manager.state.add_scan(s2)

            # Handle failure
            redistributed = manager.handle_node_failure("node-b")

            assert len(redistributed) == 2
            # Node should be offline
            failed_node = manager.state.get_node("node-b")
            assert failed_node.status == NodeStatus.OFFLINE

            # Scans should be reassigned
            scan1 = manager.state.backend.load_scan("s1")
            assert scan1.status == "running"  # Re-assigned to another node
        finally:
            manager.stop()

    def test_handle_node_failure_no_scans(self, manager, node_b):
        """Test handling a node failure with no pending scans."""
        manager.start()
        try:
            manager.state.add_node(node_b)
            redistributed = manager.handle_node_failure("node-b")
            assert len(redistributed) == 0
            assert manager.state.get_node("node-b").status == NodeStatus.OFFLINE
        finally:
            manager.stop()

    def test_get_status(self, manager, node_b):
        """Test getting cluster status."""
        manager.start()
        try:
            manager.state.add_node(node_b)
            status = manager.get_status()

            assert status["self_id"] == "test-node"
            assert status["leader_id"] == "test-node"
            assert status["nodes_total"] == 2  # self + node_b
            assert status["nodes_online"] == 2
            assert "nodes" in status
            assert "scans_total" in status
        finally:
            manager.stop()

    def test_sync_state(self, manager, node_b):
        """Test getting a state snapshot from the manager."""
        manager.start()
        try:
            manager.state.add_node(node_b)
            snapshot = manager.sync_state()

            assert "nodes" in snapshot
            assert "scans" in snapshot
            assert "leader_id" in snapshot
            assert "timestamp" in snapshot
            assert len(snapshot["nodes"]) >= 1
        finally:
            manager.stop()

    def test_merge_peer_state(self, manager):
        """Test merging peer state."""
        manager.start()
        try:
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
            manager.merge_peer_state(snapshot)

            peer = manager.state.get_node("peer-1")
            assert peer is not None
            assert peer.address == "10.0.0.5"
        finally:
            manager.stop()

    def test_is_running_flag(self, manager):
        """Test that is_running reflects manager state."""
        assert not manager.is_running
        manager.start()
        assert manager.is_running
        manager.stop()
        assert not manager.is_running

    def test_start_idempotent(self, manager):
        """Test that calling start() twice is safe."""
        manager.start()
        manager.start()  # Should not raise
        manager.stop()


# ─── Utility function tests ─────────────────────────────────────────────────


class TestUtilities:
    """Tests for utility functions."""

    def test_parse_iso_timestamp(self):
        """Test parsing ISO 8601 timestamps."""
        ts = _parse_iso_timestamp("2026-01-01T00:00:00Z")
        assert ts is not None
        assert isinstance(ts, float)

    def test_parse_iso_timestamp_with_offset(self):
        """Test parsing ISO 8601 timestamps with timezone offset."""
        ts = _parse_iso_timestamp("2026-01-01T00:00:00+00:00")
        assert ts is not None

    def test_parse_iso_timestamp_invalid(self):
        """Test parsing invalid timestamps returns None."""
        ts = _parse_iso_timestamp("not-a-timestamp")
        assert ts is None

    def test_parse_iso_timestamp_empty(self):
        """Test parsing empty string returns None."""
        ts = _parse_iso_timestamp("")
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
