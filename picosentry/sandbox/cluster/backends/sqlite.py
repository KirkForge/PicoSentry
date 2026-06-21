from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from picosentry.sandbox.cluster.backends.base import StateBackend
from picosentry.sandbox.cluster.models import ClusterNode, ScanRequest


class SQLiteStateBackend(StateBackend):
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


__all__ = ["SQLiteStateBackend"]
