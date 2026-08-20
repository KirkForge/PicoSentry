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

    def test_retire_immediate_with_zero_grace(self, monkeypatch):
        """WO6.0.0-014: grace=0 is the fail-closed setting — retire IMMEDIATELY,
        not "disable retirement forever" (the old `if grace > 0` guard did
        that). A zero grace means cutoff=now, so every non-primary token is
        stale and gets retired on the next gossip round."""
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
        assert calls == [0.0], "grace=0 must retire immediately, not skip retirement"

    def test_negative_grace_rejected_uses_default(self, monkeypatch):
        """WO6.0.0-014: a negative env value used to parse through and silently
        disable retirement forever (cutoff was always in the future). It must
        be rejected — fail closed to the default grace."""
        from picosentry.sandbox.cluster.token_store import token_grace_seconds

        monkeypatch.setenv("PICODOME_CLUSTER_TOKEN_GRACE_SECONDS", "-5")
        assert token_grace_seconds() == 3600.0, "negative grace must fall back to default"


class TestSelfRefreshTrustClamped:
    """WO6.0.0-014: a holder of an accepted token could iteratively
    self-rotate trust because apply_announcement stamped adopted candidates
    with issued_at=announced_at (announcer-chosen), giving each derived
    candidate a fresh grace clock. issued_at must be clamped to min(announced_at, now)."""

    def test_adopted_candidate_issued_at_does_not_exceed_now(self, monkeypatch):
        import hashlib
        import hmac as hmac_mod

        from picosentry.sandbox.cluster.token_store import (
            ClusterTokenStore,
            ROTATION_CONTEXT,
        )

        # The adopter's clock is BEHIND the announced_at (e.g. clock skew or a
        # replayed announcement). The old code stamped issued_at=announced_at
        # (forward of now), so the grace window ran past the adopter's now.
        monkeypatch.setattr("picosentry.sandbox.cluster.token_store.time.time", lambda: 1000.0)

        # Set up so the anchor is NOT the primary — that's the adopt_token
        # path (the buggy branch). The primary is "new-primary"; an old
        # accepted token "old-anchor" is the anchor the announcer holds.
        store = ClusterTokenStore(initial_token="old-anchor")
        store.set_primary("new-primary")  # demotes old-anchor into accepted
        assert store.is_accepted("old-anchor")
        assert store.primary_token == "new-primary"

        announced_at = 2000.0  # announcer's clock is 1000s ahead
        ctx = f"{ROTATION_CONTEXT}{announced_at}".encode()
        candidate = hmac_mod.new(b"old-anchor", ctx, hashlib.sha256).hexdigest()
        expected_hmac = hmac_mod.new(b"old-anchor", candidate.encode(), hashlib.sha256).hexdigest()
        announcement = {
            "announced_by": "peer",
            "hmac": expected_hmac,
            "announced_at": announced_at,
            "grace_expires": announced_at + 600,
        }

        assert store.apply_announcement(announcement) is True
        infos = {i.token: i for i in store.accepted_token_infos}
        assert candidate in infos, "candidate was not adopted"
        # Clamped: issued_at must not be forward of the adopter's now.
        assert infos[candidate].issued_at <= 1000.0, (
            f"issued_at={infos[candidate].issued_at} leaked the announcer's future clock"
        )

    def test_stale_announcement_cannot_reset_grace_forward(self, monkeypatch):
        """A replayed/delayed announcement must not push a candidate's grace
        window forward past the adopter's now — that's the self-refresh bug."""
        import hashlib
        import hmac as hmac_mod

        from picosentry.sandbox.cluster.token_store import (
            ClusterTokenStore,
            ROTATION_CONTEXT,
        )

        clock = {"now": 1000.0}
        monkeypatch.setattr("picosentry.sandbox.cluster.token_store.time.time", lambda: clock["now"])

        # anchor is NOT the primary (adopt_token path, the buggy branch)
        store = ClusterTokenStore(initial_token="old-anchor")
        store.set_primary("new-primary")

        announced_at = 1000.0
        ctx = f"{ROTATION_CONTEXT}{announced_at}".encode()
        candidate = hmac_mod.new(b"old-anchor", ctx, hashlib.sha256).hexdigest()
        expected_hmac = hmac_mod.new(b"old-anchor", candidate.encode(), hashlib.sha256).hexdigest()
        announcement = {
            "announced_by": "peer",
            "hmac": expected_hmac,
            "announced_at": announced_at,
            "grace_expires": announced_at + 600,
        }
        assert store.apply_announcement(announcement) is True
        assert store.is_accepted(candidate)
        # The candidate was adopted at issued_at=min(1000, 1000)=1000.

        # Time passes; the candidate is now stale.
        clock["now"] = 2000.0
        # Re-applying the SAME announcement returns False (candidate already
        # accepted) — no re-adoption, no grace reset.
        assert store.apply_announcement(announcement) is False
        # Retire everything older than now-1s. The candidate (issued_at=1000)
        # is stale and MUST be retired even though the announcement is still
        # being gossiped by a holder of old-anchor.
        store.retire_older_than(2000.0 - 1.0)
        assert not store.is_accepted(candidate), "stale candidate survived retirement (self-refresh bug)"
        # The primary is never retired.
        assert store.primary_token == "new-primary"


class TestEitherAuthDeadCode:
    """WO6.0.0-014: API-token holders were dead-coded — the outer
    _authorize_cluster_route accepted EITHER a cluster token OR an API token,
    but both handlers re-ran _check_cluster_token inside, which required an
    X-Cluster-Token header → API tokens always 403'd. The redundant inner
    check is gone; an API token with the right permission must reach the
    handler."""

    def test_api_token_can_fetch_cluster_snapshot(self, tmp_path, monkeypatch):
        import http.client
        import socket

        import picosentry.sandbox.audit.logger as audit_logger_mod
        from picosentry.sandbox.audit import AuditLogger
        from picosentry.sandbox.tenant import reset_tenant_registry

        API_TOKEN = "picodome-admin-cluster-route-test-0001"
        CLUSTER_TOKEN = "cluster-token-wo014"
        audit_logger_mod._audit_logger = AuditLogger(log_dir=tmp_path / "audit", max_bytes=1024 * 1024)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        finally:
            s.close()

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

        from picosentry.sandbox.daemon.server import PicoDomeDaemon

        daemon = PicoDomeDaemon(host="127.0.0.1", port=port)
        daemon.start(background=True)
        # wait for health
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                conn.request("GET", "/health")
                r = conn.getresponse()
                r.read()
                conn.close()
                if r.status == 200:
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise TimeoutError("daemon did not become healthy")
        try:
            # API token (admin role → scan:read) must reach the snapshot handler.
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request(
                "GET",
                "/api/v1/cluster/snapshot",
                headers={"Authorization": f"Bearer {API_TOKEN}"},
            )
            resp = conn.getresponse()
            body = resp.read()
            conn.close()
            assert resp.status == 200, f"API token rejected (the EITHER-auth dead code): {body!r}"
            # The snapshot must be a real JSON object, not the 403 cluster-token-required error.
            assert json.loads(body).get("cluster") != "inactive" or "nodes" in json.loads(body)

            # Cluster token path still works (regression — the inner check removal
            # must not have broken the cluster-token branch of _authorize_cluster_route).
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request(
                "GET",
                "/api/v1/cluster/snapshot",
                headers={"X-Cluster-Token": CLUSTER_TOKEN},
            )
            resp = conn.getresponse()
            body = resp.read()
            conn.close()
            assert resp.status == 200, f"cluster token path broke: {body!r}"
        finally:
            daemon.stop()
            reset_tenant_registry()


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
