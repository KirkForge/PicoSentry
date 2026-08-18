"""Cluster trust + partition-healing tests — WO4.0.0-019 (P2, partial).

Covers the landed subset:
- Gossip snapshots carry token digests, never secret material
- Slow-cadence OFFLINE-peer re-probe heals a transient partition
- Scheduled token retirement runs on the gossip cadence
- JSONL store enforces max_jobs at runtime (not only at load)
"""

from __future__ import annotations

import json
import time


from picosentry.sandbox.cluster import MemoryStateBackend
from picosentry.sandbox.cluster.models import ClusterNode, NodeStatus
from picosentry.sandbox.cluster.orchestrator import ClusterManager
from picosentry.sandbox.cluster.state import ClusterState
from picosentry.sandbox.cluster.token_store import token_digest
from picosentry.sandbox.daemon.store import PersistentScanJobStore

TOKEN = "cluster-trust-token-wo019"


def _state_with_token(token: str = TOKEN) -> ClusterState:
    return ClusterState(backend=MemoryStateBackend(), cluster_token=token)


class TestSnapshotCarriesNoSecrets:
    def test_snapshot_has_digests_not_tokens(self):
        state = _state_with_token("primary-secret-value")
        state.token_store.rotate("rotated-secret-value")

        raw = json.dumps(state.get_state_snapshot())
        assert "primary-secret-value" not in raw
        assert "rotated-secret-value" not in raw
        ts = state.get_state_snapshot()["token_store"]
        assert ts["primary"]["digest"] == token_digest("rotated-secret-value")
        assert all("digest" in entry and "token" not in entry for entry in ts["accepted"])

    def test_legacy_cluster_token_field_is_gone(self):
        snapshot = _state_with_token().get_state_snapshot()
        assert "cluster_token" not in snapshot


class TestPartitionHealing:
    def _make_manager(self, node_id: str, token: str = TOKEN) -> ClusterManager:
        mgr = ClusterManager(
            address="127.0.0.1",
            port=8500,
            node_id=node_id,
            backend=MemoryStateBackend(),
            heartbeat_interval=9999,
            heartbeat_timeout=9999,
            cluster_token=token,
        )
        mgr.start()
        return mgr

    def _mock_urlopen_returning(self, snapshot: dict):
        def mock_urlopen(req, timeout=None, context=None):
            class MockResponse:
                def read(self, n=-1):
                    body = json.dumps(snapshot).encode()
                    return body[:n] if n is not None and n >= 0 else body

                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

            return MockResponse()

        return mock_urlopen

    def test_offline_peer_is_reprobed_and_heals(self, monkeypatch):
        """After a transient partition (both sides OFFLINE), the slow-cadence
        re-probe must reach the offline peer and heal it via merge."""
        alpha = self._make_manager("alpha")
        beta = self._make_manager("beta")

        # Register each other as peers (as _add_peers in the 3-node tests).
        for mgr, other in ((alpha, beta), (beta, alpha)):
            other_self = other.state.get_node(other.node_id)
            assert other_self is not None
            mgr.state.add_node(
                ClusterNode(
                    node_id=other.node_id,
                    address=other_self.address,
                    port=other.port,
                    status=NodeStatus.ONLINE,
                    last_heartbeat=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    load=0,
                )
            )
        try:
            # Partition from beta's view: alpha missed heartbeats → OFFLINE.
            alpha_node = beta.state.get_node("alpha")
            assert alpha_node is not None
            alpha_node.status = NodeStatus.OFFLINE
            beta.state.update_node(alpha_node)

            # A live peer keeps heartbeating — each self-update bumps its
            # version counter past the offline marker (per-node counters).
            for _ in range(4):
                self_node = alpha.state.get_node("alpha")
                assert self_node is not None
                self_node.last_heartbeat = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                alpha.state.update_node(self_node)

            probed: list[str] = []

            def mock_urlopen(req, timeout=None, context=None):
                probed.append(req.full_url)
                return self._mock_urlopen_returning(alpha.sync_state())(req, timeout, context)

            monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)

            # Normal round: ONLINE peers only → alpha (OFFLINE) not probed.
            beta._gossip_round(include_offline=False)
            assert probed == [], "OFFLINE peer must not be probed on regular cadence"

            # Slow-cadence round: alpha is probed and its ONLINE self-record
            # heals beta's view via merge.
            beta._gossip_round(include_offline=True)
            assert len(probed) == 1, "OFFLINE peer must be probed on re-probe rounds"
            healed = beta.state.get_node("alpha")
            assert healed is not None
            assert healed.status == NodeStatus.ONLINE, "partition did not heal"
        finally:
            alpha.stop()
            beta.stop()


class TestScheduledTokenRetirement:
    def test_retire_runs_when_configured(self, monkeypatch):
        mgr = ClusterManager(
            node_id="retire-node",
            backend=MemoryStateBackend(),
            heartbeat_interval=9999,
            cluster_token=TOKEN,
        )
        calls: list[float] = []
        monkeypatch.setattr(mgr, "retire_stale_tokens", lambda grace: calls.append(grace) or 0)
        monkeypatch.setenv("PICODOME_CLUSTER_TOKEN_GRACE_SECONDS", "1234")

        mgr._retire_tokens_if_configured()
        assert calls == [1234.0]

    def test_retire_disabled_with_zero_grace(self, monkeypatch):
        mgr = ClusterManager(
            node_id="retire-node",
            backend=MemoryStateBackend(),
            heartbeat_interval=9999,
            cluster_token=TOKEN,
        )
        calls: list[float] = []
        monkeypatch.setattr(mgr, "retire_stale_tokens", lambda grace: calls.append(grace) or 0)
        monkeypatch.setenv("PICODOME_CLUSTER_TOKEN_GRACE_SECONDS", "0")

        mgr._retire_tokens_if_configured()
        assert calls == []


class TestJsonlRuntimeCap:
    def test_add_enforces_max_jobs_at_runtime(self, tmp_path):
        store = PersistentScanJobStore(store_dir=tmp_path, max_jobs=5)
        for i in range(8):
            store.add(f"job-{i}", ["echo", str(i)], "tester")
        assert len(store.list_recent(limit=100)) == 5
        # Oldest evicted, newest retained.
        ids = {j["job_id"] for j in store.list_recent(limit=100)}
        assert "job-7" in ids and "job-0" not in ids

    def test_add_only_workload_compacts_dead_weight(self, tmp_path):
        """WO5.0.0-030: add() only appends, so evicted jobs pile up as dead
        lines between full rewrites. Bounded compaction keeps the file within
        ~2x the live set (max_jobs cap pattern)."""
        store = PersistentScanJobStore(store_dir=tmp_path, max_jobs=4)
        for i in range(20):
            store.add(f"job-{i}", ["echo", str(i)], "tester")

        lines = (tmp_path / "jobs.jsonl").read_text().splitlines()
        assert len(lines) <= 2 * 4, f"unbounded growth: {len(lines)} lines for 4 live jobs"
        live = {j["job_id"] for j in store.list_recent(limit=100)}
        assert live == {f"job-{i}" for i in range(16, 20)}
        for line in lines:
            assert json.loads(line)["job_id"] in live, "compacted file kept a dead line"


class TestDaemonRetentionScheduler:
    def test_interval_parsing(self, monkeypatch):
        from picosentry.sandbox.daemon.daemon import PicoDomeDaemon

        daemon = PicoDomeDaemon.__new__(PicoDomeDaemon)
        monkeypatch.setenv("PICODOME_RETENTION_INTERVAL_SECONDS", "3600")
        assert daemon._retention_interval() == 3600.0
        monkeypatch.setenv("PICODOME_RETENTION_INTERVAL_SECONDS", "0")
        assert daemon._retention_interval() == 0.0
        monkeypatch.setenv("PICODOME_RETENTION_INTERVAL_SECONDS", "not-a-number")
        assert daemon._retention_interval() == 86400.0
