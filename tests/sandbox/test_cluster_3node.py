"""3-node cluster integration tests for hardened gossip.

These tests exercise the production-hardened cluster code paths without
spinning up real HTTP servers:

- Leader election converges across three independent managers.
- Shared cluster tokens are enforced before state is merged.
- Monotonic version counters win merge conflicts deterministically.
- Scans redistribute when a node fails.
- The gossip client sends the cluster token header.
- Managers shut down gracefully and remove themselves from local state.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

import pytest

from picosentry.sandbox.cluster import MemoryStateBackend
from picosentry.sandbox.cluster.models import ClusterNode, NodeStatus, ScanRequest
from picosentry.sandbox.cluster.orchestrator import ClusterManager


TOKEN = "cluster-token-integration-test"


def _make_manager(
    node_id: str,
    port: int,
    token: str = TOKEN,
    heartbeat_interval: int = 9999,
) -> ClusterManager:
    """Create a started ClusterManager with an isolated memory backend."""
    from picosentry.sandbox.cluster import MemoryStateBackend

    mgr = ClusterManager(
        address="127.0.0.1",
        port=port,
        node_id=node_id,
        backend=MemoryStateBackend(),
        heartbeat_interval=heartbeat_interval,
        heartbeat_timeout=9999,
        cluster_token=token,
    )
    mgr.start()
    return mgr


def _add_peers(mgr: ClusterManager, peers: list[ClusterManager]) -> None:
    """Register other managers as peer nodes in *mgr*'s state."""
    for peer in peers:
        if peer.node_id == mgr.node_id:
            continue
        peer_self = peer.state.get_node(peer.node_id)
        assert peer_self is not None
        node = ClusterNode(
            node_id=peer.node_id,
            address=peer_self.address,
            port=peer.port,
            status=NodeStatus.ONLINE,
            last_heartbeat=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            load=0,
        )
        mgr.state.add_node(node)


def _full_mesh_merge(managers: list[ClusterManager]) -> None:
    """Exchange snapshots so every manager sees every other manager's state."""
    snapshots = [m.sync_state() for m in managers]
    for idx, receiver in enumerate(managers):
        for j, snap in enumerate(snapshots):
            if j == idx:
                continue
            receiver.merge_peer_state(snap)


class TestThreeNodeCluster:
    """End-to-end tests with three real ClusterManager instances."""

    def test_leader_consensus_after_full_mesh_merge(self):
        """After all nodes gossip, every node agrees on the lowest-id leader."""
        m1 = _make_manager("alpha", 8444)
        m2 = _make_manager("beta", 8445)
        m3 = _make_manager("gamma", 8446)

        _add_peers(m1, [m2, m3])
        _add_peers(m2, [m1, m3])
        _add_peers(m3, [m1, m2])

        try:
            _full_mesh_merge([m1, m2, m3])

            assert m1.state.get_leader_id() == "alpha"
            assert m2.state.get_leader_id() == "alpha"
            assert m3.state.get_leader_id() == "alpha"

            # Token is present in every snapshot
            for m in (m1, m2, m3):
                assert m.sync_state().get("cluster_token") == TOKEN
        finally:
            for m in (m1, m2, m3):
                m.stop()

    def test_scan_distribution_and_failure_redistribution(self):
        """A scan assigned to one node is redistributed when that node fails."""
        m1 = _make_manager("alpha", 8444)
        m2 = _make_manager("beta", 8445)
        m3 = _make_manager("gamma", 8446)

        _add_peers(m1, [m2, m3])
        _add_peers(m2, [m1, m3])
        _add_peers(m3, [m1, m2])

        _full_mesh_merge([m1, m2, m3])

        try:
            # Submit scan through the leader manager
            scan = ScanRequest(scan_id="dist-001", command=["echo", "hello"])
            m1.assign_scan(scan)

            # Propagate the assignment to the other managers
            snap1 = m1.sync_state()
            m2.merge_peer_state(snap1)
            m3.merge_peer_state(snap1)

            # All three should see the scan assigned to alpha (least loaded / lowest id)
            for m in (m1, m2, m3):
                s = m.state.backend.load_scan("dist-001")
                assert s is not None
                assert s.assigned_node == "alpha"
                assert s.status == "running"

            # Simulate alpha failing from beta's point of view
            redistributed = m2.handle_node_failure("alpha")
            assert "dist-001" in redistributed

            # Beta now has the scan redistributed to beta or gamma
            scan_beta = m2.state.backend.load_scan("dist-001")
            assert scan_beta.assigned_node in ("beta", "gamma")
            assert scan_beta.status == "running"

            # Propagate the updated state back so alpha's manager sees the failure
            snap2 = m2.sync_state()
            m1.merge_peer_state(snap2)
            m3.merge_peer_state(snap2)

            alpha_node = m1.state.get_node("alpha")
            assert alpha_node is not None
            assert alpha_node.status == NodeStatus.OFFLINE
        finally:
            for m in (m1, m2, m3):
                m.stop()

    def test_cluster_token_mismatch_rejects_merge(self):
        """A manager with a mismatched token cannot merge the cluster snapshot."""
        m1 = _make_manager("alpha", 8444, token="secret-a")
        m2 = _make_manager("beta", 8445, token="secret-b")

        _add_peers(m1, [m2])
        _add_peers(m2, [m1])

        try:
            snap1 = m1.sync_state()
            with pytest.raises(ValueError, match="cluster token mismatch"):
                m2.merge_peer_state(snap1)

            snap2 = m2.sync_state()
            with pytest.raises(ValueError, match="cluster token mismatch"):
                m1.merge_peer_state(snap2)
        finally:
            m1.stop()
            m2.stop()

    def test_version_wins_over_older_heartbeat(self):
        """A lower-version node record is not allowed to overwrite a newer one."""
        from picosentry.sandbox.cluster.state import ClusterState
        from picosentry.sandbox.cluster import MemoryStateBackend

        state = ClusterState(backend=MemoryStateBackend(), cluster_token=TOKEN)
        node = ClusterNode(
            node_id="versioned",
            address="10.0.0.1",
            last_heartbeat="2026-06-16T12:00:00Z",
            load=0,
        )
        state.add_node(node)
        original_version = state.get_node("versioned").version

        # Older heartbeat but explicitly lower version — should lose
        old_node = ClusterNode(
            node_id="versioned",
            address="10.0.0.99",
            last_heartbeat="2026-06-16T10:00:00Z",
            load=99,
            version=original_version - 1,
        )
        state.merge_state(
            {
                "nodes": [old_node.to_dict()],
                "scans": [],
                "cluster_token": TOKEN,
            }
        )

        winner = state.get_node("versioned")
        assert winner.address == "10.0.0.1"
        assert winner.load == 0
        assert winner.version == original_version

    def test_gossip_client_sends_cluster_token_header(self, monkeypatch):
        """_fetch_and_merge_peer includes X-Cluster-Token when one is configured."""
        captured: dict[str, Any] = {}

        def mock_urlopen(req, timeout=None, context=None):
            captured["headers"] = dict(req.headers)
            captured["url"] = req.full_url

            class MockResponse:
                def read(self):
                    return json.dumps(
                        {
                            "nodes": [],
                            "scans": [],
                            "cluster_token": TOKEN,
                        }
                    ).encode()

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            return MockResponse()

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)

        mgr = ClusterManager(
            address="127.0.0.1",
            port=8444,
            node_id="client",
            backend=MemoryStateBackend(),
            cluster_token=TOKEN,
        )
        mgr._state.add_node(ClusterNode(node_id="client", address="127.0.0.1", port=8444))
        peer = ClusterNode(node_id="peer", address="10.0.0.2", port=8444)

        mgr._fetch_and_merge_peer(peer)

        assert captured.get("headers", {}).get("X-cluster-token") == TOKEN
        assert captured.get("url", "").startswith("http://")

    def test_gossip_client_uses_https_when_tls_configured(self, monkeypatch):
        """_fetch_and_merge_peer switches to https when TLS material is provided."""
        captured: dict[str, Any] = {}

        def mock_urlopen(req, timeout=None, context=None):
            captured["url"] = req.full_url
            captured["context"] = context

            class MockResponse:
                def read(self):
                    return json.dumps(
                        {
                            "nodes": [],
                            "scans": [],
                            "cluster_token": TOKEN,
                        }
                    ).encode()

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            return MockResponse()

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)

        import ssl

        monkeypatch.setattr(
            ssl.SSLContext,
            "load_verify_locations",
            lambda self, cafile=None, capath=None, cadata=None: None,
        )

        mgr = ClusterManager(
            address="127.0.0.1",
            port=8444,
            node_id="tls-client",
            backend=MemoryStateBackend(),
            cluster_token=TOKEN,
            tls_ca_path="/tmp/ca.pem",
        )
        mgr._state.add_node(ClusterNode(node_id="tls-client", address="127.0.0.1", port=8444))
        peer = ClusterNode(node_id="peer", address="10.0.0.2", port=8444)

        mgr._fetch_and_merge_peer(peer)

        assert captured.get("url", "").startswith("https://")
        assert captured.get("context") is not None

    def test_graceful_shutdown_removes_self(self):
        """Stopping a manager removes its own node and re-elects a leader."""
        m1 = _make_manager("alpha", 8444)
        m2 = _make_manager("beta", 8445)

        _add_peers(m1, [m2])
        _add_peers(m2, [m1])
        _full_mesh_merge([m1, m2])

        assert m1.state.get_leader_id() == "alpha"

        try:
            m1.stop()

            # alpha is gone from alpha's own state
            assert m1.state.get_node("alpha") is None
            # beta remains and should become leader
            m1.state.elect_leader()
            assert m1.state.get_leader_id() == "beta"
        finally:
            m2.stop()


class TestClusterTokenThreadSafety:
    """Token is immutable under the state lock."""

    def test_set_cluster_token_is_thread_safe(self):
        """Concurrent set_cluster_token calls do not corrupt state."""
        from picosentry.sandbox.cluster.state import ClusterState
        from picosentry.sandbox.cluster import MemoryStateBackend

        state = ClusterState(backend=MemoryStateBackend())
        errors: list[Exception] = []

        def set_tokens():
            try:
                for i in range(100):
                    state.set_cluster_token(f"token-{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=set_tokens) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert state.cluster_token.startswith("token-")
