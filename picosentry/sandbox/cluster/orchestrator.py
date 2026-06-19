from __future__ import annotations

import contextlib
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
    try:

        ts = ts.replace("Z", "+00:00")
        from datetime import datetime

        dt = datetime.fromisoformat(ts)
        return dt.timestamp()
    except (ValueError, TypeError):

        try:
            import calendar

            t = time.strptime(ts.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
            return calendar.timegm(t)
        except (ValueError, TypeError):
            return None


class ClusterManager:

    def __init__(
        self,
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
    ) -> None:
        self._address = address
        self._port = port
        self._node_id = node_id or ClusterNode.generate_id()
        self._state = ClusterState(backend, cluster_token=cluster_token)
        self._heartbeat_interval = heartbeat_interval
        self._heartbeat_timeout = heartbeat_timeout
        self._max_missed_heartbeats = max_missed_heartbeats
        self._cluster_token = cluster_token
        self._tls_cert_path = tls_cert_path
        self._tls_key_path = tls_key_path
        self._tls_ca_path = tls_ca_path
        self._running = False
        self._heartbeat_thread: threading.Thread | None = None
        self._health_check_thread: threading.Thread | None = None
        self._gossip_thread: threading.Thread | None = None
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

    @property
    def cluster_token(self) -> str:
        return self._cluster_token

    @property
    def address(self) -> str:
        return self._address

    @property
    def port(self) -> int:
        return self._port


    def start(self) -> None:
        self._stop_event.clear()
        if self._running:
            logger.warning("Cluster manager already running")
            return

        self._running = True


        self_node = ClusterNode(
            node_id=self._node_id,
            address=self._address,
            port=self._port,
            status=NodeStatus.ONLINE,
            last_heartbeat=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            load=0,
        )
        self._state.add_node(self_node)


        if len(self._state.list_nodes(status=NodeStatus.ONLINE)) == 1:
            self._state.elect_leader()


        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
            name="picodome-cluster-heartbeat",
        )
        self._heartbeat_thread.start()


        self._health_check_thread = threading.Thread(
            target=self._health_check_loop,
            daemon=True,
            name="picodome-cluster-health",
        )
        self._health_check_thread.start()


        self._gossip_thread = threading.Thread(
            target=self._gossip_loop,
            daemon=True,
            name="picodome-cluster-gossip",
        )
        self._gossip_thread.start()


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
        if not self._running:
            return

        self._running = False
        self._stop_event.set()


        node = self._state.get_node(self._node_id)
        if node:
            node.status = NodeStatus.DRAINING
            self._state.update_node(node)


        time.sleep(0.1)


        if node:
            node.status = NodeStatus.OFFLINE
            self._state.update_node(node)


        for thread in (self._heartbeat_thread, self._health_check_thread, self._gossip_thread):
            if thread is not None and thread.is_alive():
                thread.join(timeout=5.0)


        self._state.remove_node(self._node_id)


        leader_id = self._state.get_leader_id()
        if leader_id == self._node_id or leader_id is None:
            self._state.elect_leader()


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


    def assign_scan(self, scan_request: ScanRequest) -> ClusterNode | None:

        self._state.add_scan(scan_request)


        node = self._state.assign_scan(scan_request.scan_id)


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


    def sync_state(self) -> dict[str, Any]:
        return self._state.get_state_snapshot()

    def merge_peer_state(self, snapshot: dict[str, Any]) -> None:
        self._state.merge_state(snapshot)


    def handle_heartbeat(self, node_id: str, status: str = "online", load: int = 0) -> ClusterNode | None:
        node = self._state.get_node(node_id)
        if node is None:
            logger.warning("Heartbeat from unknown node: %s", node_id)
            return None

        try:
            node.status = NodeStatus(status) if isinstance(status, str) else status
        except ValueError:
            logger.warning("Invalid heartbeat status '%s' from node %s", status, node_id)
            return None
        node.last_heartbeat = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        node.load = load
        self._state.update_node(node)

        logger.debug("Heartbeat from %s: status=%s load=%d", node_id, status, load)
        return node


    def handle_node_failure(self, node_id: str) -> list[str]:
        node = self._state.get_node(node_id)
        if node is None:
            logger.warning("Node failure for unknown node: %s", node_id)
            return []


        node.status = NodeStatus.OFFLINE
        self._state.update_node(node)


        failed_scans = self._state.get_scans_for_node(node_id)
        redistributed = []

        for scan in failed_scans:

            self._state.fail_scan(scan.scan_id)
            redistributed.append(scan.scan_id)


            new_node = self._state.assign_scan(scan.scan_id)
            if new_node:
                logger.info("Scan %s redistributed from %s to %s", scan.scan_id, node_id, new_node.node_id)
            else:
                logger.warning("No available node for scan %s (was on failed node %s)", scan.scan_id, node_id)


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


    def get_status(self) -> dict[str, Any]:
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


    def _heartbeat_loop(self) -> None:
        while self._running:
            try:
                node = self._state.get_node(self._node_id)
                if node:
                    node.last_heartbeat = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    self._state.update_node(node)
            except Exception:
                logger.exception("Heartbeat update failed")

            self._stop_event.wait(timeout=self._heartbeat_interval)

    def _health_check_loop(self) -> None:
        while self._running:
            try:
                self._check_node_health()
            except Exception:
                logger.exception("Health check failed")

            self._stop_event.wait(timeout=self._heartbeat_timeout)

    def _check_node_health(self) -> None:
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

    def _gossip_loop(self) -> None:
        """Periodically exchange cluster state with peers via HTTP(S).

        Every ``heartbeat_interval * 3`` seconds, this loop:
        1. Finds all ONLINE peers (excluding self)
        2. GETs their /api/v1/cluster/snapshot
        3. Merges the returned snapshot into local state

        This is what turns the gossip primitives into an actual
        self-converging cluster without a central coordinator.
        """
        # Run less frequently than heartbeats — gossip is heavier (HTTP call).
        gossip_interval = self._heartbeat_interval * 3

        while self._running:
            try:
                peers = [
                    n for n in self._state.list_nodes(status=NodeStatus.ONLINE)
                    if n.node_id != self._node_id
                ]
                for peer in peers:
                    try:
                        self._fetch_and_merge_peer(peer)
                    except Exception as e:
                        logger.debug("Gossip with peer %s failed: %s", peer.node_id, e)
            except Exception:
                logger.exception("Gossip loop error")

            self._stop_event.wait(timeout=gossip_interval)

    def _fetch_and_merge_peer(self, peer: ClusterNode) -> None:
        """Fetch snapshot from a single peer and merge it into local state."""
        import json
        import ssl
        from urllib.request import Request, urlopen

        scheme = "https" if self._tls_ca_path or self._tls_cert_path else "http"
        # Honor an explicit scheme already present in the peer address.
        if peer.address.startswith(("http://", "https://")):
            base_url = f"{peer.address}:{peer.port}/api/v1/cluster/snapshot"
        else:
            base_url = f"{scheme}://{peer.address}:{peer.port}/api/v1/cluster/snapshot"

        headers: dict[str, str] = {"Accept": "application/json"}
        if self._cluster_token:
            headers["X-Cluster-Token"] = self._cluster_token

        req = Request(base_url, headers=headers)

        kwargs: dict[str, Any] = {"timeout": 5.0}
        if scheme == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            with contextlib.suppress(AttributeError):
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            if self._tls_ca_path:
                ctx.load_verify_locations(cafile=self._tls_ca_path)
            else:
                ctx.load_default_certs()
            if self._tls_cert_path and self._tls_key_path:
                ctx.load_cert_chain(certfile=self._tls_cert_path, keyfile=self._tls_key_path)
            ctx.check_hostname = False
            kwargs["context"] = ctx

        with urlopen(req, **kwargs) as resp:
            snapshot = json.loads(resp.read())

        if not isinstance(snapshot, dict):
            logger.debug("Peer %s returned invalid snapshot", peer.node_id)
            return

        self.merge_peer_state(snapshot)
        logger.debug(
            "Gossip: merged state from %s (%d nodes, %d scans)",
            peer.node_id,
            len(snapshot.get("nodes", [])),
            len(snapshot.get("scans", [])),
        )


__all__ = ["ClusterManager", "_parse_iso_timestamp"]
