"""WO7.0.0-019: versioned policy loads verify companion signatures."""

from __future__ import annotations

from pathlib import Path

import pytest

from picosentry.sandbox.l3.models import Policy, PolicyRule, RuleTarget, SyscallAction
from picosentry.sandbox.policy_versioned import VersionedPolicyStore
from picosentry.sandbox.policy_versioned.signing import generate_key, key_to_hex


@pytest.fixture
def store(tmp_path: Path) -> VersionedPolicyStore:
    return VersionedPolicyStore(store_dir=tmp_path / "policies")


@pytest.fixture
def sample_policy() -> Policy:
    return Policy(
        name="signed-policy",
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


def test_save_and_load_with_signature(store, sample_policy, monkeypatch):
    """A policy saved with a signing key can be loaded with verification."""
    key = generate_key()
    monkeypatch.setenv("PICODOME_POLICY_KEY", key_to_hex(key))

    pv = store.save(sample_policy, author="admin", change_description="Initial")
    assert pv.version == 1

    v_path = store._store_dir / "signed-policy" / "v1.json"
    assert v_path.with_suffix(".json.sig").is_file(), "vN.json.sig was not written"

    loaded = store.load("signed-policy", version=1)
    assert loaded is not None
    assert loaded.version == 1


def test_load_tampered_versioned_file_rejected(store, sample_policy, monkeypatch):
    """A tampered vN.json fails signature verification on load."""
    key = generate_key()
    monkeypatch.setenv("PICODOME_POLICY_KEY", key_to_hex(key))

    store.save(sample_policy, author="admin", change_description="Initial")
    v_path = store._store_dir / "signed-policy" / "v1.json"
    content = v_path.read_text()
    tampered = content.replace('"signed-policy"', '"evil-policy"')
    v_path.write_text(tampered)

    loaded = store.load("signed-policy", version=1)
    assert loaded is None, "tampered vN.json should not load with verify_signature=True"


def test_load_missing_sig_with_key_rejected(store, sample_policy, monkeypatch):
    """A vN.json without a .sig fails when a key is configured."""
    key = generate_key()
    monkeypatch.setenv("PICODOME_POLICY_KEY", key_to_hex(key))

    store.save(sample_policy, author="admin", change_description="Initial")
    v_sig = store._store_dir / "signed-policy" / "v1.json.sig"
    v_sig.unlink()

    loaded = store.load("signed-policy", version=1)
    assert loaded is None


def test_load_without_key_no_sig_ok(store, sample_policy):
    """No key + no sig = unsigned policy loads fine (dev mode)."""
    store.save(sample_policy, author="admin", change_description="Initial")
    loaded = store.load("signed-policy", version=1)
    assert loaded is not None


def test_load_verify_signature_false_bypasses(store, sample_policy, monkeypatch):
    """verify_signature=False loads even a tampered file."""
    key = generate_key()
    monkeypatch.setenv("PICODOME_POLICY_KEY", key_to_hex(key))

    store.save(sample_policy, author="admin", change_description="Initial")
    v_path = store._store_dir / "signed-policy" / "v1.json"
    content = v_path.read_text()
    v_path.write_text(content.replace('"signed-policy"', '"evil-policy"'))

    loaded = store.load("signed-policy", version=1, verify_signature=False)
    assert loaded is not None
