"""WO5.0.0-004 — cluster gossip must survive API-token auth.

The daemon boots with PICODOME_API_TOKENS *and* PICODOME_CLUSTER_TOKEN set
(the configuration where gossip used to 401). A real ClusterManager peer
runs the orchestrator's EXACT gossip request (Accept + X-Cluster-Token,
never Authorization) against the real HTTP daemon:

- GET /api/v1/cluster/snapshot → 200, snapshot merged into the peer
- POST /api/v1/cluster/snapshot with X-Cluster-Token → 200, merged
- both sides converge (each manager lists both nodes)
- no-auth request → 401; wrong cluster token → 403
"""

from __future__ import annotations

import http.client
import json
import socket
import time

import pytest

import picosentry.sandbox.audit.logger as audit_logger_mod
import picosentry.sandbox.cluster.manager as cluster_manager_mod
from picosentry.sandbox.audit import AuditLogger
from picosentry.sandbox.cluster.models import ClusterNode, NodeStatus
from picosentry.sandbox.cluster.orchestrator import ClusterManager
from picosentry.sandbox.cluster import MemoryStateBackend
from picosentry.sandbox.daemon.server import PicoDomeDaemon
from picosentry.sandbox.tenant import reset_tenant_registry

API_TOKEN = "picodome-reader-cluster-auth-token-000001"
CLUSTER_TOKEN = "cluster-secret-gossip-token-0001"
PEER_ID = "peer-node-1"


@pytest.fixture(autouse=True)
def _clean_singletons():
    original_audit = audit_logger_mod._audit_logger
    original_cluster = cluster_manager_mod._cluster_manager
    from picosentry.sandbox.daemon.handler import PicoDomeHandler

    saved = (PicoDomeHandler.scan_executor, PicoDomeHandler.scan_slots)
    yield
    PicoDomeHandler.scan_executor, PicoDomeHandler.scan_slots = saved
    audit_logger_mod._audit_logger = original_audit
    cluster_manager_mod._cluster_manager = original_cluster
    reset_tenant_registry()


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _req(port: int, method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


def _wait_healthy(port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, _ = _req(port, "GET", "/health")
            if status == 200:
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("daemon did not become healthy")


class TestClusterGossipWithApiAuth:
    def test_orchestrator_gossip_request_succeeds_and_peers_converge(self, tmp_path, monkeypatch):
        audit_logger_mod._audit_logger = AuditLogger(log_dir=tmp_path / "audit", max_bytes=1024 * 1024)

        port = _free_port()
        for key, value in {
            "PICODOME_JOB_STORE_DIR": str(tmp_path / "jobs"),
            "PICODOME_API_TOKENS": API_TOKEN,
            "PICODOME_CLUSTER_TOKEN": CLUSTER_TOKEN,
            "PICODOME_CLUSTER_ADDRESS": "127.0.0.1",
            "PICODOME_CLUSTER_PORT": str(port),
            "PICODOME_CLUSTER_HEARTBEAT_INTERVAL": "9999",
            "PICODOME_CLUSTER_HEARTBEAT_TIMEOUT": "9999",
        }.items():
            monkeypatch.setenv(key, value)

        daemon = PicoDomeDaemon(host="127.0.0.1", port=port)
        daemon.start(background=True)
        _wait_healthy(port)

        daemon_mgr = cluster_manager_mod.get_cluster_manager()
        assert daemon_mgr.is_running

        peer = ClusterManager(
            address="127.0.0.1",
            port=_free_port(),
            node_id=PEER_ID,
            backend=MemoryStateBackend(),
            heartbeat_interval=9999,
            heartbeat_timeout=9999,
            cluster_token=CLUSTER_TOKEN,
        )
        peer.start()
        try:
            # Register the daemon as a peer node, exactly as discovery would.
            daemon_self = daemon_mgr.state.get_node(daemon_mgr.node_id)
            peer.state.add_node(
                ClusterNode(
                    node_id=daemon_mgr.node_id,
                    address=daemon_self.address,
                    port=port,
                    status=NodeStatus.ONLINE,
                    last_heartbeat=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    load=0,
                )
            )

            # The orchestrator's EXACT gossip request: GET with Accept +
            # X-Cluster-Token only (no Authorization) — used to 401.
            peer._fetch_and_merge_peer(peer.state.get_node(daemon_mgr.node_id))
            merged_nodes = {n.node_id for n in peer.state.list_nodes()}
            assert daemon_mgr.node_id in merged_nodes, "peer did not merge daemon snapshot (gossip 401?)"

            # Push direction: POST the peer's snapshot with the cluster token.
            snapshot = json.dumps(peer.sync_state()).encode()
            status, body = _req(
                port,
                "POST",
                "/api/v1/cluster/snapshot",
                body=snapshot,
                headers={"Content-Type": "application/json", "X-Cluster-Token": CLUSTER_TOKEN},
            )
            assert status == 200, body
            assert json.loads(body)["status"] == "merged"

            # Convergence: the daemon now knows the peer too.
            status, data = _req(
                port,
                "GET",
                "/api/v1/cluster/snapshot",
                headers={"Accept": "application/json", "X-Cluster-Token": CLUSTER_TOKEN},
            )
            assert status == 200, data
            node_ids = {n["node_id"] for n in json.loads(data)["nodes"]}
            assert PEER_ID in node_ids
            assert daemon_mgr.node_id in node_ids

            # Negative: unauthenticated gossip is still rejected.
            status, _ = _req(port, "GET", "/api/v1/cluster/snapshot", headers={"Accept": "application/json"})
            assert status == 401

            # Negative: wrong cluster token.
            status, _ = _req(
                port,
                "GET",
                "/api/v1/cluster/snapshot",
                headers={"Accept": "application/json", "X-Cluster-Token": "wrong"},
            )
            assert status == 403

            # Negative: wrong cluster token on POST too.
            status, _ = _req(
                port,
                "POST",
                "/api/v1/cluster/snapshot",
                body=snapshot,
                headers={"Content-Type": "application/json", "X-Cluster-Token": "wrong"},
            )
            assert status == 403
        finally:
            peer.stop()
            daemon.stop()

    def test_api_token_alone_still_required_for_other_routes(self, tmp_path, monkeypatch):
        """The bypass is narrow: cluster token does NOT authenticate /api/v1/scans."""
        audit_logger_mod._audit_logger = AuditLogger(log_dir=tmp_path / "audit", max_bytes=1024 * 1024)
        port = _free_port()
        for key, value in {
            "PICODOME_JOB_STORE_DIR": str(tmp_path / "jobs"),
            "PICODOME_API_TOKENS": API_TOKEN,
            "PICODOME_CLUSTER_TOKEN": CLUSTER_TOKEN,
            "PICODOME_CLUSTER_HEARTBEAT_INTERVAL": "9999",
        }.items():
            monkeypatch.setenv(key, value)
        daemon = PicoDomeDaemon(host="127.0.0.1", port=port)
        daemon.start(background=True)
        _wait_healthy(port)
        try:
            status, _ = _req(
                port, "GET", "/api/v1/scans", headers={"Accept": "application/json", "X-Cluster-Token": CLUSTER_TOKEN}
            )
            assert status == 401, "cluster token leaked into non-cluster routes"
        finally:
            daemon.stop()
