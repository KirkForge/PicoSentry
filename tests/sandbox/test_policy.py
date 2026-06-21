"""Tests for L3 policy module — presets, import/export, validation."""

import json
import tempfile
from pathlib import Path

import pytest

from picosentry.sandbox.l3.models import Policy, PolicyRule, RuleTarget, SyscallAction
from picosentry.sandbox.l3.policy import default_policy, load_policy


class TestPolicyPresets:
    def test_default_policy_structure(self):
        policy = default_policy()
        assert policy.name == "picodome-default"
        assert policy.version == "1.0"
        assert policy.default_action == SyscallAction.DENY
        assert len(policy.rules) >= 5  # At least the core rules

    def test_default_policy_file_read_rules(self):
        policy = default_policy()
        read_rules = [r for r in policy.rules if r.target == RuleTarget.FILE_READ]
        assert len(read_rules) >= 1
        for r in read_rules:
            assert r.action == SyscallAction.ALLOW

    def test_default_policy_network_rules(self):
        policy = default_policy()
        net_rules = [r for r in policy.rules if r.target in (RuleTarget.NETWORK_OUT, RuleTarget.NETWORK_IN)]
        assert len(net_rules) >= 1

    def test_default_policy_deny_network_out(self):
        policy = default_policy()
        net_out_rules = [r for r in policy.rules if r.target == RuleTarget.NETWORK_OUT]
        deny_rules = [r for r in net_out_rules if r.action == SyscallAction.DENY]
        assert len(deny_rules) >= 1

    def test_default_policy_deny_process_spawn(self):
        policy = default_policy()
        spawn_rules = [r for r in policy.rules if r.target == RuleTarget.PROCESS_SPAWN]
        assert len(spawn_rules) >= 1
        for r in spawn_rules:
            assert r.action == SyscallAction.DENY

    def test_default_policy_deny_network_bind(self):
        policy = default_policy()
        bind_rules = [r for r in policy.rules if r.target == RuleTarget.NETWORK_BIND]
        assert len(bind_rules) >= 1
        for r in bind_rules:
            assert r.action == SyscallAction.DENY

    def test_default_policy_allow_dns(self):
        policy = default_policy()
        dns_rules = [r for r in policy.rules if r.target == RuleTarget.DNS_QUERY]
        assert len(dns_rules) >= 1
        for r in dns_rules:
            assert r.action == SyscallAction.ALLOW

    def test_default_policy_to_dict_roundtrip(self):
        policy = default_policy()
        d = policy.to_dict()
        # Verify JSON-serializable
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        assert parsed["name"] == "picodome-default"


class TestPolicyImportExport:
    def test_export_to_json_file(self):
        policy = default_policy()
        d = policy.to_dict()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(d, f, indent=2)
            path = Path(f.name)

        loaded = load_policy(path)
        assert loaded.name == policy.name
        assert len(loaded.rules) == len(policy.rules)

    def test_import_custom_policy(self):
        data = {
            "name": "custom-strict",
            "version": "1.0",
            "default_action": "deny",
            "rules": [
                {
                    "rule_id": "STRICT-001",
                    "target": "network_out",
                    "action": "deny",
                    "description": "No network",
                },
            ],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = Path(f.name)

        policy = load_policy(path)
        assert policy.name == "custom-strict"
        assert policy.default_action == SyscallAction.DENY
        assert len(policy.rules) == 1
        assert policy.rules[0].rule_id == "STRICT-001"

    def test_roundtrip_preserves_rules(self):
        original = default_policy()
        d = original.to_dict()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(d, f, indent=2)
            path = Path(f.name)

        loaded = load_policy(path)
        assert loaded.name == original.name
        assert len(loaded.rules) == len(original.rules)
        for orig, load in zip(original.rules, loaded.rules, strict=True):
            assert orig.rule_id == load.rule_id
            assert orig.target == load.target
            assert orig.action == load.action


class TestPolicyValidation:
    def test_all_rule_ids_unique(self):
        policy = default_policy()
        ids = [r.rule_id for r in policy.rules]
        assert len(ids) == len(set(ids))

    def test_all_targets_valid(self):
        policy = default_policy()
        for r in policy.rules:
            assert r.target in RuleTarget

    def test_all_actions_valid(self):
        policy = default_policy()
        for r in policy.rules:
            assert r.action in SyscallAction

    def test_empty_policy_is_valid(self):
        policy = Policy(name="empty")
        assert len(policy.rules) == 0

    def test_custom_policy_with_all_targets(self):
        """A policy can have rules for every target type."""
        rules = []
        for i, target in enumerate(RuleTarget):
            rules.append(
                PolicyRule(
                    rule_id=f"TEST-{i:03d}",
                    target=target,
                    action=SyscallAction.DENY,
                )
            )
        policy = Policy(name="all-targets", rules=rules)
        assert len(policy.rules) == len(RuleTarget)


class TestStrictPreset:
    def test_strict_policy_deny_all(self):
        """A strict policy should deny everything by default."""
        policy = Policy(
            name="strict",
            default_action=SyscallAction.DENY,
            rules=[],  # No allow rules
        )
        assert policy.default_action == SyscallAction.DENY
        assert len(policy.rules) == 0


class TestNodePreset:
    def test_node_preset(self):
        """Simulate a node-like policy."""
        policy = Policy(
            name="node-preset",
            default_action=SyscallAction.DENY,
            rules=[
                PolicyRule(
                    rule_id="NODE-001",
                    target=RuleTarget.FILE_READ,
                    action=SyscallAction.ALLOW,
                    paths=["**/node_modules/**", "**/*.js"],
                    description="Read JS files",
                ),
                PolicyRule(
                    rule_id="NODE-002",
                    target=RuleTarget.FILE_WRITE,
                    action=SyscallAction.ALLOW,
                    paths=["/tmp/**"],
                    description="Write to tmp",
                ),
                PolicyRule(
                    rule_id="NODE-003",
                    target=RuleTarget.NETWORK_OUT,
                    action=SyscallAction.DENY,
                    description="Block network",
                ),
            ],
        )
        assert policy.name == "node-preset"
        assert len(policy.rules) == 3


class TestPythonPreset:
    def test_python_preset(self):
        """Simulate a python-like policy."""
        policy = Policy(
            name="python-preset",
            default_action=SyscallAction.DENY,
            rules=[
                PolicyRule(
                    rule_id="PY-001",
                    target=RuleTarget.FILE_READ,
                    action=SyscallAction.ALLOW,
                    paths=["/usr/lib/python*/**", "**/site-packages/**"],
                    description="Read Python libs",
                ),
                PolicyRule(
                    rule_id="PY-002",
                    target=RuleTarget.FILE_WRITE,
                    action=SyscallAction.ALLOW,
                    paths=["/tmp/**"],
                    description="Write to tmp",
                ),
                PolicyRule(
                    rule_id="PY-003",
                    target=RuleTarget.NETWORK_OUT,
                    action=SyscallAction.DENY,
                    description="Block network",
                ),
                PolicyRule(
                    rule_id="PY-004",
                    target=RuleTarget.PROCESS_SPAWN,
                    action=SyscallAction.DENY,
                    description="Block spawns",
                ),
            ],
        )
        assert policy.name == "python-preset"
        assert len(policy.rules) == 4


class TestCustomPolicyCreation:
    def test_create_custom_policy(self):
        policy = Policy(
            name="my-custom",
            version="2.0",
            default_action=SyscallAction.ALLOW,
            rules=[
                PolicyRule(
                    rule_id="CUSTOM-001",
                    target=RuleTarget.NETWORK_OUT,
                    action=SyscallAction.DENY,
                    addresses=["evil.com"],
                    description="Block evil.com",
                ),
            ],
        )
        assert policy.name == "my-custom"
        assert policy.version == "2.0"
        assert policy.default_action == SyscallAction.ALLOW
        assert len(policy.rules) == 1
        assert policy.rules[0].addresses == ["evil.com"]

    def test_policy_with_syscalls(self):
        policy = Policy(
            name="syscall-policy",
            rules=[
                PolicyRule(
                    rule_id="SYS-001",
                    target=RuleTarget.SYSCALL_GENERIC,
                    action=SyscallAction.DENY,
                    syscalls=["execve", "fork", "clone"],
                    description="Block dangerous syscalls",
                ),
            ],
        )
        assert policy.rules[0].syscalls == ["execve", "fork", "clone"]

    def test_policy_with_paths_and_addresses(self):
        policy = Policy(
            name="mixed-policy",
            rules=[
                PolicyRule(
                    rule_id="MIXED-001",
                    target=RuleTarget.FILE_READ,
                    action=SyscallAction.ALLOW,
                    paths=["/usr/**", "/lib/**"],
                    addresses=[],
                ),
                PolicyRule(
                    rule_id="MIXED-002",
                    target=RuleTarget.NETWORK_OUT,
                    action=SyscallAction.DENY,
                    paths=[],
                    addresses=["0.0.0.0/0"],
                ),
            ],
        )
        assert policy.rules[0].paths == ["/usr/**", "/lib/**"]
        assert policy.rules[1].addresses == ["0.0.0.0/0"]


# ── Strict, Node, Python preset policies ────────────────────────────────


class TestPolicyBuiltins:
    def test_strict_policy(self):
        from picosentry.sandbox.l3.policy import strict_policy

        policy = strict_policy()
        assert policy.name == "picodome-strict"
        assert policy.default_action == SyscallAction.DENY

    def test_node_policy(self):
        from picosentry.sandbox.l3.policy import node_policy

        policy = node_policy()
        assert policy.name == "picodome-node"
        assert policy.default_action == SyscallAction.DENY

    def test_python_policy_builtin(self):
        from picosentry.sandbox.l3.policy import python_policy

        policy = python_policy()
        assert policy.name == "picodome-python"
        assert policy.default_action == SyscallAction.DENY


# ── Export / Import round-trip ─────────────────────────────────────────────


class TestPolicyExportImport:
    def test_export_and_import_roundtrip(self, tmp_path):
        from picosentry.sandbox.l3.policy import default_policy, export_policy, import_policy

        original = default_policy()
        path = tmp_path / "exported-policy.json"
        export_policy(original, path)
        assert path.exists()

        loaded = import_policy(path)
        assert loaded.name == original.name
        assert loaded.version == original.version
        assert len(loaded.rules) == len(original.rules)

    def test_import_nonexistent_file(self, tmp_path):
        from picosentry.sandbox.l3.policy import import_policy

        with pytest.raises((FileNotFoundError, ValueError)):
            import_policy(tmp_path / "nonexistent.json")

    def test_import_invalid_policy(self, tmp_path):
        from picosentry.sandbox.l3.policy import import_policy

        path = tmp_path / "bad-policy.json"
        path.write_text('{"name": "bad", "version": "1", "default_action": "deny", "rules": []}')
        with pytest.raises(ValueError):
            import_policy(path)


# ── Policy validation ────────────────────────────────────────────────────


class TestPolicyValidationExtra:
    def test_validate_empty_policy(self):
        from picosentry.sandbox.l3.policy import validate_policy

        empty = Policy(name="empty", version="1.0", default_action=SyscallAction.DENY, rules=[])
        errors = validate_policy(empty)
        assert len(errors) >= 1
        assert any("no rules" in e.lower() for e in errors)

    def test_validate_duplicate_rule_ids(self):
        from picosentry.sandbox.l3.policy import validate_policy

        dup = Policy(
            name="dup",
            version="1.0",
            default_action=SyscallAction.DENY,
            rules=[
                PolicyRule(rule_id="DUP-001", target=RuleTarget.NETWORK_OUT, action=SyscallAction.DENY),
                PolicyRule(rule_id="DUP-001", target=RuleTarget.FILE_READ, action=SyscallAction.ALLOW),
            ],
        )
        errors = validate_policy(dup)
        assert any("Duplicate rule ID" in e for e in errors)

    def test_validate_good_policy(self):
        from picosentry.sandbox.l3.policy import validate_policy

        good = default_policy()
        errors = validate_policy(good)
        assert errors == []


# ── load_policy from file ─────────────────────────────────────────────────


class TestLoadPolicy:
    def test_load_policy_from_json_file(self, tmp_path):
        from picosentry.sandbox.l3.policy import load_policy

        policy_data = {
            "name": "test-loaded",
            "version": "2.0",
            "default_action": "deny",
            "rules": [
                {
                    "rule_id": "FILE-001",
                    "target": "file_read",
                    "action": "allow",
                    "paths": ["/tmp/**"],
                    "description": "Allow reads from /tmp",
                },
            ],
        }
        path = tmp_path / "test-policy.json"
        path.write_text(json.dumps(policy_data))
        policy = load_policy(path)
        assert policy.name == "test-loaded"

    def test_load_policy_by_name(self):
        from picosentry.sandbox.l3.policy import load_policy

        policy = load_policy(name="default")
        assert policy.name == "picodome-default"

    def test_load_policy_by_name_strict(self):
        from picosentry.sandbox.l3.policy import load_policy

        policy = load_policy(name="strict")
        assert policy.name == "picodome-strict"

    def test_load_policy_invalid_name(self):
        from picosentry.sandbox.l3.policy import load_policy

        with pytest.raises(ValueError, match="Invalid policy name"):
            load_policy(name="../etc/passwd")

    def test_load_policy_no_args_returns_default(self):
        from picosentry.sandbox.l3.policy import load_policy

        policy = load_policy()
        assert policy.name == "picodome-default"
