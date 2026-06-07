from __future__ import annotations

from picosentry.sandbox.cluster.models import ClusterNode, ScanRequest


class StateBackend:

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


__all__ = ["StateBackend"]
