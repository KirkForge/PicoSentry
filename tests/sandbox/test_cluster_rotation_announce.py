"""WO5.0.0-030 — cluster token rotation announcements + trust ceilings.

Gate coverage:
- 3-node rotation: primary rotated on node A, announcement propagates via
  gossip snapshots, every node accepts (and follows) the new token, the old
  token keeps working within grace and retires after it (monkeypatched clock,
  no wall sleeps).
- No secret material on the wire: raw new-token bytes appear in NO snapshot;
  the announcement carries exactly {announced_by, hmac, announced_at,
  grace_expires}.
- Real-daemon route auth: GET /api/v1/cluster/snapshot authenticates with the
  NEW token (200), the OLD token within grace (200), and a wrong token (403).
- Rolling-upgrade compatibility: unknown token_store fields (including
  announcements old nodes never read) do not break merges; unverifiable
  announcements never bypass the shared-trust check; legacy raw snapshots
  carrying an announcement field still merge.
"""

from __future__ import annotations

import http.client
import json
import socket
import time
from typing import Any

import pytest

import picosentry.sandbox.audit.logger as audit_logger_mod
import picosentry.sandbox.cluster.manager as cluster_manager_mod
from picosentry.sandbox.audit import AuditLogger
from picosentry.sandbox.cluster import MemoryStateBackend
from picosentry.sandbox.cluster.models import ClusterNode, NodeStatus
from picosentry.sandbox.cluster.orchestrator import ClusterManager
from picosentry.sandbox.cluster.state import ClusterState
from picosentry.sandbox.cluster.token_store import (
    ROTATION_CONTEXT,
    derive_rotation_token,
)
from picosentry.sandbox.tenant import reset_tenant_registry

TOKEN_V1 = "rotation-gate-token-v1"
GRACE_SECONDS = 600


class FakeClock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def time(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _state_with_token(token: str = TOKEN_V1) -> ClusterState:
    return ClusterState(backend=MemoryStateBackend(), cluster_token=token)


def _make_manager(node_id: str, port: int, token: str = TOKEN_V1) -> ClusterManager:
    mgr = ClusterManager(
        address="127.0.0.1",
        port=port,
        node_id=node_id,
        backend=MemoryStateBackend(),
        heartbeat_interval=9999,
        heartbeat_timeout=9999,
        cluster_token=token,
    )
    mgr.start()
    return mgr


def _add_peers(mgr: ClusterManager, peers: list[ClusterManager]) -> None:
    for peer in peers:
        if peer.node_id == mgr.node_id:
            continue
        peer_self = peer.state.get_node(peer.node_id)
        assert peer_self is not None
        mgr.state.add_node(
            ClusterNode(
                node_id=peer.node_id,
                address=peer_self.address,
                port=peer.port,
                status=NodeStatus.ONLINE,
                last_heartbeat=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                load=0,
            )
        )


def _full_mesh_merge(managers: list[ClusterManager]) -> None:
    snapshots = [m.sync_state() for m in managers]
    for idx, receiver in enumerate(managers):
        for j, snap in enumerate(snapshots):
            if j != idx:
                receiver.merge_peer_state(snap)


class TestRotationAnnouncementUnit:
    def test_generated_rotation_announces_explicit_does_not(self, monkeypatch):
        monkeypatch.setenv("PICODOME_CLUSTER_TOKEN_GRACE_SECONDS", str(GRACE_SECONDS))
        store = _state_with_token("anchor-secret").token_store

        store.rotate("manual-secret")
        assert store.announcement is None, "explicit tokens are not peer-derivable; no announcement"

        store2 = _state_with_token("anchor-secret").token_store
        store2.rotate(announced_by="alpha")
        announcement = store2.announcement
        assert announcement is not None
        assert set(announcement) == {"announced_by", "hmac", "announced_at", "grace_expires"}
        assert announcement["announced_by"] == "alpha"
        assert announcement["grace_expires"] == announcement["announced_at"] + GRACE_SECONDS
        derived = derive_rotation_token("anchor-secret", announcement["announced_at"])
        assert derived == store2.primary_token
        assert derived != "anchor-secret"

    def test_announcement_hmac_is_keyed_digest_of_new_under_old(self, monkeypatch):
        import hashlib
        import hmac as hmac_mod

        monkeypatch.setenv("PICODOME_CLUSTER_TOKEN_GRACE_SECONDS", "60")
        store = _state_with_token("anchor-secret").token_store
        store.rotate()
        announcement = store.announcement
        assert announcement is not None
        derived = derive_rotation_token("anchor-secret", announcement["announced_at"])
        expected = hmac_mod.new(b"anchor-secret", derived.encode(), hashlib.sha256).hexdigest()
        assert announcement["hmac"] == expected

    def test_derive_is_context_separated(self):
        assert derive_rotation_token("a", 1.0) != derive_rotation_token("a", 2.0)
        assert derive_rotation_token("a", 1.0) != derive_rotation_token("b", 1.0)
        assert ROTATION_CONTEXT in "picodome-cluster-rotation:v1:"

    def test_apply_announcement_rejects_junk(self):
        store = _state_with_token("anchor").token_store
        assert store.apply_announcement({"hmac": "no", "announced_at": "x"}) is False
        assert store.apply_announcement({"hmac": "ab" * 32, "announced_at": 5.0}) is False
        assert store.apply_announcement({}) is False

    def test_rotation_restarts_grace_clock_on_demoted_primary(self, monkeypatch):
        clock = FakeClock(1000.0)
        monkeypatch.setattr("picosentry.sandbox.cluster.token_store.time.time", clock.time)
        store = _state_with_token("old-token").token_store
        clock.advance(5000.0)
        store.rotate()
        infos = {i.token: i for i in store.accepted_token_infos}
        assert infos["old-token"].issued_at == 6000.0, "grace must run from rotation, not original issue (1000.0)"


class TestApplyAnnouncementToctou:
    """WO6.0.0-014 TOCTOU rider: ``apply_announcement`` must hold its lock
    across the anchor decision AND the promotion. The prior code released the
    lock between the two, so a concurrent ``rotate()`` could clobber the state
    the promotion was based on.

    The tooth is a deterministic lock-held assertion: the promotion helpers
    (``_set_primary_locked`` / ``_adopt_token_locked``) are only safe to call
    when ``self._lock`` is already held by the current thread. A
    non-reentrant ``threading.Lock`` cannot be re-acquired by the holder, so
    if ``apply_announcement`` released the lock before promoting, a concurrent
    ``acquire(blocking=False)`` from another thread would SUCCEED during the
    promotion — proving the gap. The fixed code holds the lock throughout, so
    the concurrent acquire fails for the whole window.
    """

    def test_promotion_runs_under_held_lock(self, monkeypatch):
        store = _state_with_token("toctou-anchor").token_store
        lock = store._lock

        # Instrument the promotion path: whenever the locked helpers run, the
        # store lock MUST already be held by apply_announcement's `with` block.
        # threading.Lock is non-reentrant: acquire(blocking=False) returns False
        # when the lock is already held (by the current thread), True when it
        # was acquired (so we must release it to avoid leaking the lock). If
        # apply_announcement released the lock between the decision and the
        # promotion, this acquire would succeed — the TOCTOU.
        promotion_under_lock: list[bool] = []

        real_set_primary_locked = store._set_primary_locked
        real_adopt_locked = store._adopt_token_locked

        def _lock_is_held() -> bool:
            got = lock.acquire(blocking=False)
            if got:
                lock.release()
                return False
            return True

        def checked_set_primary_locked(token: str):
            promotion_under_lock.append(_lock_is_held())
            return real_set_primary_locked(token)

        def checked_adopt_locked(token, version, issued_at):
            promotion_under_lock.append(_lock_is_held())
            return real_adopt_locked(token, version, issued_at)

        monkeypatch.setattr(store, "_set_primary_locked", checked_set_primary_locked)
        monkeypatch.setattr(store, "_adopt_token_locked", checked_adopt_locked)

        # Drive a follow-rotation announcement (anchor == primary branch).
        import hashlib
        import hmac as hmac_mod

        announced_at = 1234.0
        anchor = "toctou-anchor"
        candidate = derive_rotation_token(anchor, announced_at)
        ann = {
            "announced_by": "peer",
            "hmac": hmac_mod.new(anchor.encode("utf-8"), candidate.encode("utf-8"), hashlib.sha256).hexdigest(),
            "announced_at": announced_at,
            "grace_expires": announced_at + 60,
        }
        assert store.apply_announcement(ann) is True
        assert promotion_under_lock, "promotion helpers were never called"
        assert all(promotion_under_lock), f"promotion ran without the lock held (TOCTOU gap): {promotion_under_lock}"
        assert store.primary_token == candidate, "follow-rotation did not promote the candidate"

        # Drive an adopt (anchor != primary branch): rotate first so the anchor
        # is a non-primary accepted token.
        store2 = _state_with_token("anchor-a").token_store
        store2.rotate("explicit-primary")  # anchor-a is now accepted, not primary
        lock2 = store2._lock
        adopt_checked: list[bool] = []
        real_adopt2 = store2._adopt_token_locked

        def checked_adopt2(token, version, issued_at):
            got = lock2.acquire(blocking=False)
            if got:
                lock2.release()
                adopt_checked.append(False)
            else:
                adopt_checked.append(True)
            return real_adopt2(token, version, issued_at)

        monkeypatch.setattr(store2, "_adopt_token_locked", checked_adopt2)
        candidate2 = derive_rotation_token("anchor-a", announced_at)
        ann2 = {
            "announced_by": "peer",
            "hmac": hmac_mod.new(b"anchor-a", candidate2.encode("utf-8"), hashlib.sha256).hexdigest(),
            "announced_at": announced_at,
            "grace_expires": announced_at + 60,
        }
        assert store2.apply_announcement(ann2) is True
        assert adopt_checked, "adopt helper was never called"
        assert all(adopt_checked), f"adopt ran without the lock held (TOCTOU gap): {adopt_checked}"

    def test_concurrent_apply_announcement_and_rotate_stay_consistent(self, monkeypatch):
        """Stress test: real threads hammering apply_announcement + rotate must
        leave the store internally consistent. The TOCTOU fix (single lock
        scope) is what makes this pass; under the old gap a concurrent rotate
        could retire the announcement's anchor between decision and promotion,
        leaving a stored announcement that verifies against no accepted token.

        Kept small (2 threads, 30 iterations) to stay well under the 60s test
        timeout — the deterministic ``test_promotion_runs_under_held_lock`` is
        the primary tooth; this is a consistency backstop under real scheduling.
        """
        import hashlib
        import hmac as hmac_mod
        import threading

        clock = FakeClock(1_000_000.0)
        _time_lock = threading.Lock()

        def safe_time() -> float:
            with _time_lock:
                return clock.time()

        monkeypatch.setattr("picosentry.sandbox.cluster.token_store.time.time", safe_time)
        monkeypatch.setenv("PICODOME_CLUSTER_TOKEN_GRACE_SECONDS", str(GRACE_SECONDS))

        store = _state_with_token("stress-anchor").token_store

        barrier = threading.Barrier(2)
        errors: list[Exception] = []
        iterations = 30

        def rotate_worker() -> None:
            try:
                barrier.wait()
                for _ in range(iterations):
                    clock.advance(1.0)
                    store.rotate(announced_by="rotator")
            except Exception as exc:
                errors.append(exc)

        def announce_worker() -> None:
            try:
                barrier.wait()
                for _ in range(iterations):
                    with _time_lock:
                        now = clock.time()
                    primary = store.primary_token
                    if not primary:
                        continue
                    cand = derive_rotation_token(primary, now)
                    h = hmac_mod.new(primary.encode("utf-8"), cand.encode("utf-8"), hashlib.sha256).hexdigest()
                    ann = {
                        "announced_by": "peer",
                        "hmac": h,
                        "announced_at": now,
                        "grace_expires": now + GRACE_SECONDS,
                    }
                    clock.advance(0.5)
                    store.apply_announcement(ann)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=rotate_worker), threading.Thread(target=announce_worker)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=20)

        assert errors == [], f"worker threads raised: {errors}"

        # The strong invariant: if an announcement is stored, it MUST verify
        # against some currently-accepted token. The TOCTOU gap could leave a
        # stored announcement whose anchor was retired between decision and
        # the announcement store — unverifiable against current state.
        primary = store.primary_token
        assert primary, "store ended with no primary"
        assert store.is_accepted(primary), "primary not in accepted set (clobbered)"
        announcement = store.announcement
        if announcement is not None:
            ctx = f"{ROTATION_CONTEXT}{float(announcement['announced_at'])}".encode()
            verified = False
            for tok in store.accepted_tokens:
                cand = hmac_mod.new(tok.encode("utf-8"), ctx, hashlib.sha256).hexdigest()
                expected = hmac_mod.new(tok.encode("utf-8"), cand.encode("utf-8"), hashlib.sha256).hexdigest()
                if hmac_mod.compare_digest(expected, announcement["hmac"]):
                    verified = True
                    break
            assert verified, (
                f"stored announcement verifies against NO accepted token — "
                f"the decision/promotion gap was clobbered: {announcement}"
            )


class TestThreeNodeRotationGate:
    """The WO gate: rotate on A → announce → adopt everywhere → grace → retire."""

    def test_rotate_announce_adopt_retire_full_cycle(self, monkeypatch):
        clock = FakeClock(1000.0)
        monkeypatch.setattr("picosentry.sandbox.cluster.token_store.time.time", clock.time)
        monkeypatch.setenv("PICODOME_CLUSTER_TOKEN_GRACE_SECONDS", str(GRACE_SECONDS))

        alpha = _make_manager("alpha", 8601)
        beta = _make_manager("beta", 8602)
        gamma = _make_manager("gamma", 8603)
        managers = [alpha, beta, gamma]
        try:
            _add_peers(alpha, [beta, gamma])
            _add_peers(beta, [alpha, gamma])
            _add_peers(gamma, [alpha, beta])
            _full_mesh_merge(managers)

            result = alpha.rotate_token()
            assert result["announced"] is True
            new_token = alpha.cluster_token
            assert new_token != TOKEN_V1

            for m in managers:
                snap = m.sync_state()
                raw = json.dumps(snap)
                assert new_token not in raw, "snapshot leaked the raw new token"
                assert TOKEN_V1 not in raw, "snapshot leaked the raw old token"

            _full_mesh_merge(managers)

            for m in managers:
                assert m.token_store.is_accepted(new_token), f"{m.node_id} did not adopt the new token"
                assert m.token_store.is_accepted(TOKEN_V1), f"{m.node_id} dropped the old token within grace"
                assert m.cluster_token == new_token, f"{m.node_id} did not follow the rotation"

            snap = beta.sync_state()["token_store"]
            announcement = snap["announcement"]
            assert announcement is not None, "adopters must re-broadcast the announcement"
            assert set(announcement) == {"announced_by", "hmac", "announced_at", "grace_expires"}
            assert announcement["announced_by"] == "alpha"

            clock.advance(GRACE_SECONDS - 1)
            for m in managers:
                assert m.retire_stale_tokens(GRACE_SECONDS) == 0
                assert m.token_store.is_accepted(TOKEN_V1), "old token retired before grace expiry"

            clock.advance(2)
            for m in managers:
                assert m.retire_stale_tokens(GRACE_SECONDS) == 1
                assert not m.token_store.is_accepted(TOKEN_V1), "old token outlived grace"
                assert m.token_store.is_accepted(new_token)
                assert m.cluster_token == new_token

            beta.merge_peer_state(alpha.sync_state())
        finally:
            for m in managers:
                m.stop()

    def test_node_that_missed_announcement_keeps_old_token_loudly(self, monkeypatch, caplog):
        """A partitioned node that never sees the announcement keeps its token
        (no silent merge/brain-split); the mismatch is logged for operators."""
        clock = FakeClock(1000.0)
        monkeypatch.setattr("picosentry.sandbox.cluster.token_store.time.time", clock.time)
        monkeypatch.setenv("PICODOME_CLUSTER_TOKEN_GRACE_SECONDS", str(GRACE_SECONDS))

        alpha = _make_manager("alpha", 8601)
        outsider = _make_manager("omega", 8604, token="unrelated-token")
        try:
            alpha.rotate_token()
            new_token = alpha.cluster_token

            snap = alpha.sync_state()
            with (
                pytest.raises(ValueError, match="cluster token mismatch"),
                caplog.at_level("WARNING", logger="picodome.cluster"),
            ):
                outsider.merge_peer_state(snap)
            assert any("operator" in r.message for r in caplog.records)

            assert outsider.cluster_token == "unrelated-token"
            assert not outsider.token_store.is_accepted(new_token)
        finally:
            alpha.stop()
            outsider.stop()


class TestRollingUpgradeCompatibility:
    """New node → old node must not break it; old → new keeps working."""

    def test_unknown_token_store_fields_are_ignored(self):
        local = _state_with_token("shared")
        remote = _state_with_token("shared")
        snapshot = remote.get_state_snapshot()
        snapshot["token_store"]["future_field"] = {"anything": True}
        snapshot["token_store"]["announcement"] = {"bogus": "old node never reads this"}

        local.merge_state(snapshot)
        assert local.token_store.is_accepted("shared")

    def test_unverifiable_announcement_does_not_bypass_trust(self):
        local = _state_with_token("secret-a")
        remote = _state_with_token("secret-b")
        snapshot = remote.get_state_snapshot()
        snapshot["token_store"]["announcement"] = {
            "announced_by": "evil",
            "hmac": "ab" * 32,
            "announced_at": 1234.0,
            "grace_expires": 1834.0,
        }

        with pytest.raises(ValueError, match="cluster token mismatch"):
            local.merge_state(snapshot)
        assert local.cluster_token == "secret-a"

    def test_legacy_raw_snapshot_with_announcement_field_merges(self):
        local = _state_with_token("shared")
        remote = _state_with_token("shared")
        remote.token_store.rotate("new-secret")
        legacy = {
            "nodes": [],
            "scans": [],
            "token_store": remote.token_store.to_snapshot(),
        }
        legacy["token_store"]["announcement"] = {"ignored": "by legacy parser"}

        local.merge_state(legacy)
        assert local.token_store.is_accepted("new-secret")

    def test_new_node_gossiping_to_snapshot_endpoint_shape(self):
        """The announcement survives a JSON round-trip (old nodes parse it as
        an unknown field; the daemon POST route accepts it)."""
        remote = _state_with_token("shared")
        remote.token_store.rotate()
        snapshot = json.loads(json.dumps(remote.get_state_snapshot()))
        announcement = snapshot["token_store"]["announcement"]
        assert announcement is not None
        assert isinstance(announcement["hmac"], str) and len(announcement["hmac"]) == 64
        local = _state_with_token("shared")
        local.merge_state(snapshot)
        assert local.cluster_token == remote.cluster_token


class TestDaemonRouteAuthWithRotatedToken:
    """Real HTTP daemon: the rotated token authenticates cluster routes."""

    def test_rotated_token_authenticates_snapshot_route(self, tmp_path, monkeypatch):
        audit_logger_mod._audit_logger = AuditLogger(log_dir=tmp_path / "audit", max_bytes=1024 * 1024)
        port = _free_port()
        for key, value in {
            "PICODOME_JOB_STORE_DIR": str(tmp_path / "jobs"),
            "PICODOME_CLUSTER_TOKEN": TOKEN_V1,
            "PICODOME_CLUSTER_ADDRESS": "127.0.0.1",
            "PICODOME_CLUSTER_PORT": str(port),
            "PICODOME_CLUSTER_HEARTBEAT_INTERVAL": "9999",
            "PICODOME_CLUSTER_HEARTBEAT_TIMEOUT": "9999",
            "PICODOME_CLUSTER_TOKEN_GRACE_SECONDS": str(GRACE_SECONDS),
        }.items():
            monkeypatch.setenv(key, value)

        from picosentry.sandbox.daemon.server import PicoDomeDaemon

        daemon = PicoDomeDaemon(host="127.0.0.1", port=port)
        daemon.start(background=True)
        _wait_healthy(port)
        try:
            mgr = cluster_manager_mod.get_cluster_manager()
            result = mgr.rotate_token()
            assert result["announced"] is True
            new_token = mgr.cluster_token

            status, body = _req(
                port,
                "GET",
                "/api/v1/cluster/snapshot",
                headers={"Accept": "application/json", "X-Cluster-Token": new_token},
            )
            assert status == 200, body
            assert new_token.encode() not in body, "snapshot leaked the raw new token"
            announcement = json.loads(body)["token_store"]["announcement"]
            assert announcement["announced_by"] == mgr.node_id

            status, _ = _req(
                port,
                "GET",
                "/api/v1/cluster/snapshot",
                headers={"Accept": "application/json", "X-Cluster-Token": TOKEN_V1},
            )
            assert status == 200, "old token must authenticate within grace"

            status, _ = _req(
                port,
                "GET",
                "/api/v1/cluster/snapshot",
                headers={"Accept": "application/json", "X-Cluster-Token": "wrong"},
            )
            assert status == 403
        finally:
            daemon.stop()


class TestHostnameVerificationGate:
    """WO5.0.0-030: PICODOME_CLUSTER_VERIFY_HOSTNAME=1 opts into TLS hostname
    verification for peer fetches; the default keeps the documented ceiling
    (self-signed certs addressed by IP) so rolling upgrades behave as before."""

    def _ctx_for(self, monkeypatch, env: dict[str, str]) -> bool | None:
        captured: dict[str, Any] = {}

        def mock_urlopen(req, timeout=None, context=None):
            captured["context"] = context

            class MockResponse:
                def read(self, n=-1):
                    return json.dumps({"nodes": [], "scans": [], "cluster_token": TOKEN_V1}).encode()

                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

            return MockResponse()

        import ssl

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        monkeypatch.setattr(
            ssl.SSLContext, "load_verify_locations", lambda self, cafile=None, capath=None, cadata=None: None
        )
        for key, value in env.items():
            monkeypatch.setenv(key, value)

        mgr = ClusterManager(
            address="127.0.0.1",
            port=8444,
            node_id="tls-node",
            backend=MemoryStateBackend(),
            cluster_token=TOKEN_V1,
            tls_ca_path="/tmp/ca.pem",
        )
        mgr._fetch_and_merge_peer(ClusterNode(node_id="peer", address="10.0.0.2", port=8444))
        ctx = captured.get("context")
        assert ctx is not None
        return ctx.check_hostname

    def test_hostname_verification_off_by_default(self, monkeypatch):
        assert self._ctx_for(monkeypatch, {}) is False

    def test_hostname_verification_on_when_configured(self, monkeypatch):
        assert self._ctx_for(monkeypatch, {"PICODOME_CLUSTER_VERIFY_HOSTNAME": "1"}) is True


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
