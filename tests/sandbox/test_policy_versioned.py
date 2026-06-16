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
