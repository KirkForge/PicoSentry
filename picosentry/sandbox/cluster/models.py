from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Any


DEFAULT_HEARTBEAT_INTERVAL = 10  # seconds
DEFAULT_HEARTBEAT_TIMEOUT = 30  # seconds
DEFAULT_MAX_MISSED_HEARTBEATS = 3
DEFAULT_CLUSTER_PORT = 8444  # cluster communication port (distinct from daemon 8443)


class NodeStatus(str, Enum):

    ONLINE = "online"
    OFFLINE = "offline"
    DRAINING = "draining"


@dataclass
class ClusterNode:

    node_id: str
    address: str
    port: int = DEFAULT_CLUSTER_PORT
    status: NodeStatus = NodeStatus.ONLINE
    last_heartbeat: str = ""
    load: int = 0  # scans in progress
    version: int = 0  # monotonic conflict-resolution counter
    cluster_token: str = ""  # shared cluster secret for inter-node trust

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
            "version": self.version,
            "cluster_token": self.cluster_token,
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
            version=data.get("version", 0),
            cluster_token=data.get("cluster_token", ""),
        )

    @classmethod
    def generate_id(cls) -> str:
        import socket

        hostname = socket.gethostname()
        pid = os.getpid()
        return f"picodome-{hostname}-{pid}"


@dataclass
class ScanRequest:

    scan_id: str
    command: list[str]
    priority: int = 0  # higher = more urgent
    assigned_node: str | None = None
    created_at: str = ""
    status: str = "pending"  # pending, running, completed, failed
    version: int = 0  # monotonic conflict-resolution counter

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "command": self.command,
            "priority": self.priority,
            "assigned_node": self.assigned_node,
            "created_at": self.created_at,
            "status": self.status,
            "version": self.version,
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
            version=data.get("version", 0),
        )


__all__ = [
    "DEFAULT_CLUSTER_PORT",
    "DEFAULT_HEARTBEAT_INTERVAL",
    "DEFAULT_HEARTBEAT_TIMEOUT",
    "DEFAULT_MAX_MISSED_HEARTBEATS",
    "ClusterNode",
    "NodeStatus",
    "ScanRequest",
]
