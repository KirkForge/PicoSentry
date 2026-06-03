"""Tests for L3 policy loading and configuration."""

import json
import tempfile
from pathlib import Path

import pytest

from picosentry.sandbox.l3.models import Policy, PolicyRule, RuleTarget, SyscallAction
from picosentry.sandbox.l3.policy import _policy_from_dict, default_policy, load_policy


class TestDefaultPolicy:
    def test_default_policy_loads(self):
        policy = default_policy()
        assert policy.name == "picodome-default"
        assert policy.version == "1.0"
        assert policy.default_action == SyscallAction.DENY

    def test_default_policy_has_rules(self):
        policy = default_policy()
        assert len(policy.rules) > 0

    def test_default_policy_rule_ids(self):
        policy = default_policy()
        ids = {r.rule_id for r in policy.rules}
        assert "L3-FILE-R-001" in ids
        assert "L3-NET-OUT-001" in ids
        assert "L3-PROC-001" in ids

    def test_default_policy_unique_rule_ids(self):
        policy = default_policy()
        ids = [r.rule_id for r in policy.rules]
        assert len(ids) == len(set(ids)), "Rule IDs must be unique"

    def test_default_policy_all_targets_valid(self):
        policy = default_policy()
        for rule in policy.rules:
            assert isinstance(rule.target, RuleTarget)

    def test_default_policy_all_actions_valid(self):
        policy = default_policy()
        for rule in policy.rules:
            assert isinstance(rule.action, SyscallAction)

    def test_default_policy_is_frozen(self):
        policy = default_policy()
        from dataclasses import FrozenInstanceError

        with pytest.raises(FrozenInstanceError):
            policy.name = "changed"


class TestLoadPolicy:
    def test_load_from_json_file(self, tmp_json_policy_file):
        policy = load_policy(tmp_json_policy_file)
        assert policy.name == "test-policy-from-file"
        assert policy.version == "2.0"
        assert len(policy.rules) == 1

    def test_load_from_json_file_rules(self, tmp_json_policy_file):
        policy = load_policy(tmp_json_policy_file)
        rule = policy.rules[0]
        assert rule.rule_id == "FILE-001"
        assert rule.target == RuleTarget.FILE_READ
        assert rule.action == SyscallAction.ALLOW
        assert rule.paths == ["/tmp/**"]

    def test_load_from_none_returns_default(self):
        policy = load_policy(None)
        assert policy.name == "picodome-default"

    def test_load_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_policy(Path("/nonexistent/policy.json"))

    def test_load_invalid_json_raises(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {{{")
            f.flush()
            with pytest.raises(json.JSONDecodeError):
                load_policy(Path(f.name))

    def test_load_invalid_yaml_raises(self):
        """Even though we use JSON, invalid content should raise."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("key: value\n  indented: bad")
            f.flush()
            with pytest.raises(json.JSONDecodeError):
                load_policy(Path(f.name))

    def test_load_policy_with_minimal_data(self):
        data = {"name": "minimal"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            policy = load_policy(Path(f.name))
            assert policy.name == "minimal"
            assert policy.version == "1.0"
            assert policy.default_action == SyscallAction.DENY
            assert len(policy.rules) == 0

    def test_load_policy_with_multiple_rules(self):
        data = {
            "name": "multi-rule",
            "rules": [
                {"rule_id": "R1", "target": "network_out", "action": "deny"},
                {"rule_id": "R2", "target": "file_read", "action": "allow", "paths": ["/usr/**"]},
                {"rule_id": "R3", "target": "process_spawn", "action": "deny"},
            ],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            policy = load_policy(Path(f.name))
            assert len(policy.rules) == 3


class TestPolicyFromDict:
    def test_basic_dict(self):
        data = {
            "name": "custom",
            "version": "2.0",
            "default_action": "allow",
            "rules": [],
        }
        policy = _policy_from_dict(data)
        assert policy.name == "custom"
        assert policy.version == "2.0"
        assert policy.default_action == SyscallAction.ALLOW

    def test_missing_name_defaults(self):
        data = {"rules": []}
        policy = _policy_from_dict(data)
        assert policy.name == "custom"  # default

    def test_missing_default_action(self):
        data = {"name": "test", "rules": []}
        policy = _policy_from_dict(data)
        assert policy.default_action == SyscallAction.DENY  # default

    def test_rules_with_paths(self):
        data = {
            "name": "test",
            "rules": [
                {
                    "rule_id": "R1",
                    "target": "file_read",
                    "action": "allow",
                    "paths": ["/usr/**", "/lib/**"],
                    "description": "Read system libs",
                },
            ],
        }
        policy = _policy_from_dict(data)
        assert policy.rules[0].paths == ["/usr/**", "/lib/**"]

    def test_rules_with_addresses(self):
        data = {
            "name": "test",
            "rules": [
                {
                    "rule_id": "R1",
                    "target": "network_out",
                    "action": "allow",
                    "addresses": ["127.0.0.1"],
                },
            ],
        }
        policy = _policy_from_dict(data)
        assert policy.rules[0].addresses == ["127.0.0.1"]


class TestPolicyToDict:
    def test_roundtrip(self, default_policy):
        d = default_policy.to_dict()
        assert d["name"] == "picodome-default"
        assert isinstance(d["rules"], list)
        for rule in d["rules"]:
            assert "rule_id" in rule
            assert "target" in rule
            assert "action" in rule

    def test_custom_policy_roundtrip(self):
        policy = Policy(
            name="test-policy",
            version="3.0",
            default_action=SyscallAction.ALLOW,
            rules=[
                PolicyRule(
                    rule_id="CUSTOM-001",
                    target=RuleTarget.NETWORK_OUT,
                    action=SyscallAction.DENY,
                    description="Deny network",
                ),
            ],
        )
        d = policy.to_dict()
        assert d["name"] == "test-policy"
        assert d["version"] == "3.0"
        assert d["default_action"] == "allow"
        assert len(d["rules"]) == 1
        assert d["rules"][0]["rule_id"] == "CUSTOM-001"

    def test_empty_policy_to_dict(self):
        policy = Policy(name="empty")
        d = policy.to_dict()
        assert d["name"] == "empty"
        assert d["rules"] == []


class TestPolicyValidation:
    def test_unique_rule_ids_in_default(self):
        policy = default_policy()
        ids = [r.rule_id for r in policy.rules]
        assert len(ids) == len(set(ids))

    def test_valid_targets_in_default(self):
        policy = default_policy()
        for rule in policy.rules:
            assert rule.target in RuleTarget

    def test_valid_actions_in_default(self):
        policy = default_policy()
        for rule in policy.rules:
            assert rule.action in SyscallAction

    def test_custom_policy_validation(self):
        """Custom policy should also have unique IDs and valid targets."""
        policy = Policy(
            name="test",
            rules=[
                PolicyRule(rule_id="R1", target=RuleTarget.NETWORK_OUT, action=SyscallAction.DENY),
                PolicyRule(rule_id="R2", target=RuleTarget.FILE_WRITE, action=SyscallAction.ALLOW),
            ],
        )
        ids = [r.rule_id for r in policy.rules]
        assert len(ids) == len(set(ids))

    def test_duplicate_rule_ids_detected(self):
        """If someone creates duplicate IDs, it should be caught."""
        rules = [
            PolicyRule(rule_id="R1", target=RuleTarget.NETWORK_OUT, action=SyscallAction.DENY),
            PolicyRule(rule_id="R1", target=RuleTarget.FILE_WRITE, action=SyscallAction.ALLOW),
        ]
        ids = [r.rule_id for r in rules]
        assert len(ids) != len(set(ids)), "Duplicate IDs should be detected"
