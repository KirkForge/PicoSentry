"""Tests for the versioned policy store."""

import pytest

from picosentry.sandbox.l3.models import Policy, PolicyRule, RuleTarget, SyscallAction
from picosentry.sandbox.policy_versioned import PolicyVersion, VersionedPolicyStore


@pytest.fixture
def store(tmp_path):
    return VersionedPolicyStore(store_dir=tmp_path / "policies")


@pytest.fixture
def sample_policy():
    return Policy(
        name="test-policy",
        version="1.0",
        default_action=SyscallAction.DENY,
        rules=[
            PolicyRule(
                rule_id="NET-001",
                target=RuleTarget.NETWORK_OUT,
                action=SyscallAction.DENY,
                description="Block network",
            ),
        ],
    )


class TestPolicyVersion:
    def test_from_dict_roundtrip(self, sample_policy):
        pv = PolicyVersion(
            policy=sample_policy,
            version=1,
            author="admin",
            timestamp="2025-01-01T00:00:00Z",
            change_description="Initial",
            content_hash="abc123",
        )
        d = pv.to_dict()
        pv2 = PolicyVersion.from_dict(d)
        assert pv2.version == 1
        assert pv2.author == "admin"
        assert pv2.policy.name == "test-policy"


class TestVersionedPolicyStore:
    def test_save_creates_version(self, store, sample_policy):
        pv = store.save(sample_policy, author="admin", change_description="Initial")
        assert pv.version == 1
        assert pv.author == "admin"
        assert pv.content_hash != ""

    def test_save_increments_version(self, store, sample_policy):
        store.save(sample_policy, author="admin", change_description="v1")
        pv2 = store.save(sample_policy, author="admin", change_description="v2")
        assert pv2.version == 2

    def test_load_latest(self, store, sample_policy):
        store.save(sample_policy, author="admin", change_description="v1")
        loaded = store.load("test-policy")
        assert loaded is not None
        assert loaded.version == 1

    def test_load_specific_version(self, store, sample_policy):
        store.save(sample_policy, author="admin", change_description="v1")
        store.save(sample_policy, author="admin", change_description="v2")
        loaded = store.load("test-policy", version=1)
        assert loaded is not None
        assert loaded.version == 1

    def test_load_nonexistent(self, store):
        assert store.load("nonexistent") is None

    def test_rollback(self, store, sample_policy):
        _ = store.save(sample_policy, author="admin", change_description="v1")
        # Modify policy
        modified = Policy(
            name="test-policy",
            version="2.0",
            default_action=SyscallAction.ALLOW,
            rules=[],
        )
        store.save(modified, author="admin", change_description="allow-all")
        # Rollback
        rb = store.rollback("test-policy", 1, author="admin")
        assert rb is not None
        assert rb.version == 3  # new version, not overwriting v1/v2
        assert rb.policy.default_action == SyscallAction.DENY

    def test_diff(self, store, sample_policy):
        store.save(sample_policy, author="admin", change_description="v1")
        modified = Policy(
            name="test-policy",
            default_action=SyscallAction.ALLOW,
            rules=[
                PolicyRule(rule_id="NET-002", target=RuleTarget.FILE_READ, action=SyscallAction.ALLOW, paths=["/tmp"]),
            ],
        )
        store.save(modified, author="admin", change_description="v2 with new rule")
        diff = store.diff("test-policy", 1, 2)
        assert diff["default_action_changed"] is True
        assert "NET-002" in diff["added_rules"]

    def test_list_policies(self, store, sample_policy):
        store.save(sample_policy, author="admin", change_description="v1")
        names = store.list_policies()
        assert "test-policy" in names

    def test_verify_integrity(self, store, sample_policy):
        store.save(sample_policy, author="admin", change_description="v1")
        violations = store.verify_integrity("test-policy")
        assert violations == []

    def test_content_hash_deterministic(self, store, sample_policy):
        pv1 = store.save(sample_policy, author="admin", change_description="v1")
        pv2 = store.save(sample_policy, author="admin", change_description="v2")
        assert pv1.content_hash == pv2.content_hash  # same policy = same hash


class TestVersionedPolicyStoreHardening:
    """Security regression tests for versioned policy store resilience."""

    def test_temp_file_cleaned_up_on_write_failure(self, store, sample_policy, monkeypatch, tmp_path):
        """Atomic write failures must not leave temp files behind."""
        import os

        controlled_path = tmp_path / "controlled-temp.json"

        def _controlled_mkstemp(*args, **kwargs):
            fd = os.open(str(controlled_path), os.O_CREAT | os.O_RDWR, 0o600)
            return fd, str(controlled_path)

        monkeypatch.setattr("picosentry.sandbox.policy_versioned.store.tempfile.mkstemp", _controlled_mkstemp)

        def _boom_fdopen(*args, **kwargs):
            raise RuntimeError("disk full")

        monkeypatch.setattr("picosentry.sandbox.policy_versioned.store.os.fdopen", _boom_fdopen)

        with pytest.raises(RuntimeError, match="disk full"):
            store.save(sample_policy, author="admin", change_description="boom")

        assert not controlled_path.exists()


class TestPolicyStoreEnvSplitBrain:
    """WO5.0.0-018: get_policy_store() froze its directory at first call while
    l3.policy.load_policy read PICODOME_POLICY_STORE_DIR at call time."""

    def test_singleton_follows_env_dir_change(self, tmp_path, monkeypatch, sample_policy):
        import picosentry.sandbox.policy_versioned.store as store_mod
        from picosentry.sandbox.l3.policy import load_policy

        dir_a = tmp_path / "A"
        dir_b = tmp_path / "B"
        monkeypatch.setattr(store_mod, "_policy_store", None)
        monkeypatch.setenv("PICODOME_POLICY_STORE_DIR", str(dir_a))

        store_mod.get_policy_store().save(sample_policy, author="t")
        assert (dir_a / sample_policy.name / "latest.json").is_file()

        monkeypatch.setenv("PICODOME_POLICY_STORE_DIR", str(dir_b))
        # Before the fix: the cached singleton kept writing dir A while
        # load_policy looked in dir B → FileNotFoundError split-brain.
        store_mod.get_policy_store().save(sample_policy, author="t")
        assert (dir_b / sample_policy.name / "latest.json").is_file()
        assert load_policy(name=sample_policy.name) is not None

    def test_concurrent_saves_get_distinct_versions(self, tmp_path, sample_policy):
        """WO5.0.0-018 item 9: two threads computed the same next_version and
        silently overwrote each other."""
        import threading

        from picosentry.sandbox.policy_versioned.store import VersionedPolicyStore

        store = VersionedPolicyStore(store_dir=tmp_path)
        barrier = threading.Barrier(4)

        def _save():
            barrier.wait()
            store.save(sample_policy, author="thread")

        threads = [threading.Thread(target=_save) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        versions = [v.version for v in store.list_versions(sample_policy.name)]
        assert sorted(versions) == [1, 2, 3, 4]
