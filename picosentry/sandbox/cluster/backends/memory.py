from __future__ import annotations

import threading

from picosentry.sandbox.cluster.backends.base import StateBackend
from picosentry.sandbox.cluster.models import ClusterNode, ScanRequest


class MemoryStateBackend(StateBackend):

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


__all__ = ["MemoryStateBackend"]
