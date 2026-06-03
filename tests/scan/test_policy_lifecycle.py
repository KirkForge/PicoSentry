"""Tests for policy lifecycle module."""

import json

import pytest

from picosentry.scan.policy import Policy
from picosentry.scan.policy_lifecycle import (
    InheritedPolicy,
    PolicyLayer,
    PolicyStack,
    detect_policy_drift,
    migrate_policy,
)


class TestPolicyLayer:
    def test_order(self):
        assert PolicyLayer.ORDER == ("global", "org", "repo", "pipeline")

    def test_precedence(self):
        assert PolicyLayer.precedence("global") == 0
        assert PolicyLayer.precedence("pipeline") == 3

    def test_validate(self):
        assert PolicyLayer.validate("global") is True
        assert PolicyLayer.validate("invalid") is False


class TestInheritedPolicy:
    def test_defaults(self):
        ip = InheritedPolicy(policy=Policy())
        assert ip.layer == "global"
        assert ip.last_modified != ""

    def test_invalid_layer(self):
        with pytest.raises(ValueError, match="Invalid policy layer"):
            InheritedPolicy(policy=Policy(), layer="invalid")

    def test_serialization(self):
        ip = InheritedPolicy(policy=Policy(), layer="repo", source=".picosentry-policy.yml")
        d = ip.to_dict()
        assert d["layer"] == "repo"
        restored = InheritedPolicy.from_dict(d)
        assert restored.layer == "repo"


class TestPolicyStack:
    def test_empty_stack(self):
        stack = PolicyStack()
        effective = stack.effective_policy()
        assert isinstance(effective, Policy)

    def test_single_layer(self):
        stack = PolicyStack()
        stack.add(
            InheritedPolicy(
                policy=Policy(fail_on_severity="high"),
                layer="global",
            )
        )
        effective = stack.effective_policy()
        assert effective.fail_on_severity == "high"

    def test_merge_layers(self):
        stack = PolicyStack()
        # Global: medium severity
        stack.add(
            InheritedPolicy(
                policy=Policy(fail_on_severity="medium", allow_licenses=["MIT", "Apache-2.0"]),
                layer="global",
            )
        )
        # Repo: high severity, more restrictive
        stack.add(
            InheritedPolicy(
                policy=Policy(fail_on_severity="high", allow_licenses=["MIT"]),
                layer="repo",
            )
        )
        effective = stack.effective_policy()
        # More restrictive severity wins
        assert effective.fail_on_severity == "high"
        # License intersection: only MIT
        assert "MIT" in effective.allow_licenses

    def test_drift_detection(self):
        stack = PolicyStack()
        # Global: critical severity
        stack.add(
            InheritedPolicy(
                policy=Policy(fail_on_severity="critical"),
                layer="global",
            )
        )
        # Repo: relaxes to low
        stack.add(
            InheritedPolicy(
                policy=Policy(fail_on_severity="low"),
                layer="repo",
            )
        )
        drift = stack.drift_report()
        assert len(drift["drift"]) > 0
        assert len(drift["warnings"]) > 0

    def test_no_drift(self):
        stack = PolicyStack()
        stack.add(InheritedPolicy(policy=Policy(fail_on_severity="high"), layer="global"))
        stack.add(InheritedPolicy(policy=Policy(fail_on_severity="critical"), layer="repo"))
        drift = stack.drift_report()
        # Stricter is not drift
        severity_drifts = [d for d in drift["drift"] if d["type"] == "severity_relaxation"]
        assert len(severity_drifts) == 0

    def test_remove_layer(self):
        stack = PolicyStack()
        stack.add(InheritedPolicy(policy=Policy(), layer="global"))
        assert stack.remove("global") is True
        assert stack.remove("nonexistent") is False

    def test_layers_ordering(self):
        stack = PolicyStack()
        stack.add(InheritedPolicy(policy=Policy(), layer="pipeline"))
        stack.add(InheritedPolicy(policy=Policy(), layer="global"))
        stack.add(InheritedPolicy(policy=Policy(), layer="repo"))
        layers = stack.layers()
        assert [layer.layer for layer in layers] == ["global", "repo", "pipeline"]

    def test_to_json(self):
        stack = PolicyStack()
        stack.add(InheritedPolicy(policy=Policy(), layer="global"))
        json_str = stack.to_json()
        data = json.loads(json_str)
        assert "version" in data
        assert "layers" in data
        assert "effective" in data


class TestPolicyMigration:
    def test_migrate_v0_to_v1(self):
        old = {"fail_on_severity": "high"}
        migrated = migrate_policy(old, from_version=0)
        assert migrated["version"] == 1
        assert "allow_licenses" in migrated
        assert "waivers" in migrated

    def test_migrate_preserves_values(self):
        old = {"fail_on_severity": "medium", "allow_licenses": ["MIT"]}
        migrated = migrate_policy(old, from_version=0)
        assert migrated["fail_on_severity"] == "medium"
        assert migrated["allow_licenses"] == ["MIT"]

    def test_detect_policy_drift(self):
        stack = PolicyStack()
        stack.add(InheritedPolicy(policy=Policy(fail_on_severity="critical"), layer="global"))
        stack.add(InheritedPolicy(policy=Policy(fail_on_severity="low"), layer="repo"))
        report = detect_policy_drift(stack)
        assert len(report["drift"]) > 0
