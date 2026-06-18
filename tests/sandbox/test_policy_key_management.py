"""Tests for B07 — Key management and daemon policy verification integration.

Covers:
- load_key() public API
- K8s secret mount simulation (file-based key)
- Policy verification in load_policy() with verify_signature=True
- Policy verification rejection on bad signatures
- Helm values and deployment template have policy signing config
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from picosentry.sandbox.l3.policy import load_policy
from picosentry.sandbox.policy_versioned.signing import (
    generate_key,
    key_to_hex,
    load_key,
    sign_policy_companion,
)

SAMPLE_POLICY_JSON = json.dumps(
    {
        "name": "test-policy",
        "version": "1.0",
        "default_action": "deny",
        "rules": [
            {
                "rule_id": "deny-shells",
                "target": "file_exec",
                "action": "deny",
                "paths": ["/bin/sh", "/bin/bash"],
            },
        ],
    }
)


class TestLoadKeyPublic:
    def test_load_key_from_env(self):
        key = generate_key()
        hex_str = key_to_hex(key)
        with mock.patch.dict(os.environ, {"PICODOME_POLICY_KEY": hex_str}, clear=True):
            loaded = load_key()
            assert loaded == key

    def test_load_key_from_file(self, tmp_path):
        key = generate_key()
        hex_str = key_to_hex(key)
        key_file = tmp_path / "policy.key"
        key_file.write_text(hex_str)

        with mock.patch.dict(os.environ, {"PICODOME_POLICY_KEY_FILE": str(key_file)}, clear=True):
            loaded = load_key()
            assert loaded == key

    def test_load_key_k8s_secret_mount(self, tmp_path):
        """Simulate K8s secret mount: file in /etc/picodome/keys/key"""
        key = generate_key()
        hex_str = key_to_hex(key)
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        key_file = keys_dir / "key"
        key_file.write_text(hex_str)

        with mock.patch.dict(os.environ, {"PICODOME_POLICY_KEY_FILE": str(key_file)}, clear=True):
            loaded = load_key()
            assert loaded == key

    def test_load_key_env_takes_precedence_over_file(self, tmp_path):
        key1 = generate_key()
        key2 = generate_key()
        hex1 = key_to_hex(key1)
        hex2 = key_to_hex(key2)
        key_file = tmp_path / "policy.key"
        key_file.write_text(hex2)

        with mock.patch.dict(
            os.environ,
            {
                "PICODOME_POLICY_KEY": hex1,
                "PICODOME_POLICY_KEY_FILE": str(key_file),
            },
            clear=True,
        ):
            loaded = load_key()
            assert loaded == key1  # env takes precedence

    def test_load_key_none_when_not_configured(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            assert load_key() is None

    def test_load_key_invalid_hex(self):
        with mock.patch.dict(os.environ, {"PICODOME_POLICY_KEY": "not-valid-hex"}, clear=True):
            assert load_key() is None

    def test_load_key_file_not_found(self):
        with mock.patch.dict(os.environ, {"PICODOME_POLICY_KEY_FILE": "/nonexistent/key"}, clear=True):
            assert load_key() is None


class TestPolicyVerificationInLoadPolicy:
    def test_load_policy_without_verification(self, tmp_path):
        """Policy loads normally without verify_signature."""
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(SAMPLE_POLICY_JSON)

        policy = load_policy(path=policy_file)
        assert policy.name == "test-policy"

    def test_load_policy_with_verified_companion(self, tmp_path):
        """Policy with valid companion .sig file loads successfully."""
        key = generate_key()
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(SAMPLE_POLICY_JSON)
        sign_policy_companion(policy_file, key)

        with mock.patch.dict(os.environ, {"PICODOME_POLICY_KEY": key_to_hex(key)}, clear=True):
            policy = load_policy(path=policy_file, verify_signature=True)
            assert policy.name == "test-policy"

    def test_load_policy_rejects_unsigned_with_key(self, tmp_path):
        """Unsigned policy is rejected when verify_signature=True and key is configured."""
        key = generate_key()
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(SAMPLE_POLICY_JSON)

        with (
            mock.patch.dict(os.environ, {"PICODOME_POLICY_KEY": key_to_hex(key)}, clear=True),
            pytest.raises(ValueError, match="signature verification failed"),
        ):
            load_policy(path=policy_file, verify_signature=True)

    def test_load_policy_rejects_tampered_with_key(self, tmp_path):
        """Tampered policy is rejected when verify_signature=True."""
        key = generate_key()
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(SAMPLE_POLICY_JSON)
        sign_policy_companion(policy_file, key)

        # Tamper with the policy
        tampered = json.loads(SAMPLE_POLICY_JSON)
        tampered["name"] = "tampered-policy"
        policy_file.write_text(json.dumps(tampered))

        with (
            mock.patch.dict(os.environ, {"PICODOME_POLICY_KEY": key_to_hex(key)}, clear=True),
            pytest.raises(ValueError, match="signature verification failed"),
        ):
            load_policy(path=policy_file, verify_signature=True)

    def test_load_policy_wrong_key(self, tmp_path):
        """Policy signed with one key is rejected when verified with another."""
        key1 = generate_key()
        key2 = generate_key()
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(SAMPLE_POLICY_JSON)
        sign_policy_companion(policy_file, key1)

        with (
            mock.patch.dict(os.environ, {"PICODOME_POLICY_KEY": key_to_hex(key2)}, clear=True),
            pytest.raises(ValueError, match="signature verification failed"),
        ):
            load_policy(path=policy_file, verify_signature=True)

    def test_load_named_policy_ignores_verification(self):
        """Named policies (built-in) don't need signature verification."""
        policy = load_policy(name="strict", verify_signature=True)
        assert policy.name == "picodome-strict"

    def test_default_policy_ignores_verification(self):
        """Default policy doesn't need signature verification."""
        policy = load_policy(verify_signature=True)
        assert policy.name == "picodome-default"


class TestHelmPolicySigning:
    def test_values_have_policy_signing_config(self):
        """Verify the Helm values.yaml has policySigning section."""
        repo_root = Path(__file__).resolve().parent.parent.parent
        values_path = repo_root / "deploy" / "helm" / "picodome" / "values.yaml"
        content = values_path.read_text()
        assert "policySigning" in content
        assert "verify" in content
        assert "existingSecret" in content
        assert "keyId" in content

    def test_deployment_has_policy_signing_env(self):
        """Verify the deployment template has policy signing env vars."""
        repo_root = Path(__file__).resolve().parent.parent.parent
        deploy_path = repo_root / "deploy" / "helm" / "picodome" / "templates" / "deployment.yaml"
        content = deploy_path.read_text()
        assert "PICODOME_POLICY_KEY" in content
        assert "PICODOME_POLICY_KEY_FILE" in content
        assert "PICODOME_POLICY_VERIFY" in content
        assert "policy-key" in content
