"""Tests for fleet policy rollout module."""

import unittest
from pathlib import Path

from picosentry.scan.fleet import (
    FleetManager,
    FleetTarget,
    RolloutPolicy,
    RolloutStage,
)


class TestRolloutStage(unittest.TestCase):
    """Test RolloutStage constants and validation."""

    def test_stage_order(self):
        """Rollout stages are in correct precedence order."""
        self.assertEqual(RolloutStage.precedence("canary"), 0)
        self.assertEqual(RolloutStage.precedence("staging"), 1)
        self.assertEqual(RolloutStage.precedence("production"), 2)

    def test_stage_validate(self):
        """Valid stages pass, invalid stages fail."""
        self.assertTrue(RolloutStage.validate("canary"))
        self.assertTrue(RolloutStage.validate("staging"))
        self.assertTrue(RolloutStage.validate("production"))
        self.assertFalse(RolloutStage.validate("unknown"))


class TestRolloutPolicy(unittest.TestCase):
    """Test RolloutPolicy creation and serialization."""

    def test_defaults(self):
        """RolloutPolicy has sensible defaults."""
        rp = RolloutPolicy(name="test-policy")
        self.assertEqual(rp.name, "test-policy")
        self.assertEqual(rp.stages, list(RolloutStage.ORDER))
        self.assertEqual(rp.failure_action, "rollback")
        self.assertNotEqual(rp.created_at, "")

    def test_to_dict(self):
        """RolloutPolicy serializes to dict."""
        rp = RolloutPolicy(name="test", policy_digest="sha256:abc", canary_targets=["repo:org/api"])
        d = rp.to_dict()
        self.assertEqual(d["name"], "test")
        self.assertEqual(d["policy_digest"], "sha256:abc")
        self.assertIn("repo:org/api", d["canary_targets"])

    def test_from_dict(self):
        """RolloutPolicy deserializes from dict."""
        d = {"name": "test", "policy_digest": "sha256:abc", "stages": ["canary", "production"]}
        rp = RolloutPolicy.from_dict(d)
        self.assertEqual(rp.name, "test")
        self.assertEqual(rp.policy_digest, "sha256:abc")
        self.assertEqual(rp.stages, ["canary", "production"])


class TestFleetTarget(unittest.TestCase):
    """Test FleetTarget creation and serialization."""

    def test_defaults(self):
        """FleetTarget has sensible defaults."""
        ft = FleetTarget(id="repo:org/api", name="API Server")
        self.assertEqual(ft.id, "repo:org/api")
        self.assertEqual(ft.stage, RolloutStage.PRODUCTION)
        self.assertTrue(ft.compliant)

    def test_to_dict(self):
        """FleetTarget serializes to dict."""
        ft = FleetTarget(id="repo:org/api", name="API Server", stage="canary", policy_digest="sha256:abc")
        d = ft.to_dict()
        self.assertEqual(d["id"], "repo:org/api")
        self.assertEqual(d["stage"], "canary")

    def test_from_dict(self):
        """FleetTarget deserializes from dict."""
        d = {"id": "repo:org/api", "name": "API Server", "stage": "canary", "compliant": True}
        ft = FleetTarget.from_dict(d)
        self.assertEqual(ft.id, "repo:org/api")
        self.assertEqual(ft.stage, "canary")


class TestFleetManager(unittest.TestCase):
    """Test FleetManager lifecycle operations."""

    def setUp(self):
        import tempfile

        self.tmp_dir = tempfile.mkdtemp()
        self.fm = FleetManager(data_dir=Path(self.tmp_dir) / "fleet")

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_register_target(self):
        """Targets can be registered."""
        target = FleetTarget(id="repo:org/api", name="API Server", stage="canary")
        self.fm.register_target(target)
        self.assertEqual(len(self.fm.list_targets()), 1)
        self.assertEqual(self.fm.get_target("repo:org/api").name, "API Server")

    def test_unregister_target(self):
        """Targets can be unregistered."""
        target = FleetTarget(id="repo:org/api", name="API Server")
        self.fm.register_target(target)
        self.assertTrue(self.fm.unregister_target("repo:org/api"))
        self.assertIsNone(self.fm.get_target("repo:org/api"))

    def test_unregister_nonexistent(self):
        """Unregistering nonexistent target returns False."""
        self.assertFalse(self.fm.unregister_target("nonexistent"))

    def test_list_targets_by_stage(self):
        """Targets can be filtered by stage."""
        self.fm.register_target(FleetTarget(id="t1", name="T1", stage="canary"))
        self.fm.register_target(FleetTarget(id="t2", name="T2", stage="production"))
        canary = self.fm.list_targets(stage="canary")
        self.assertEqual(len(canary), 1)
        self.assertEqual(canary[0].id, "t1")

    def test_create_rollout(self):
        """Rollouts can be created."""
        status = self.fm.create_rollout(
            name="test-rollout",
            stages=["canary", "production"],
            canary_targets=["repo:org/api"],
            created_by="admin",
        )
        self.assertEqual(status.name, "test-rollout")
        self.assertEqual(status.current_stage, "canary")

    def test_create_duplicate_rollout_raises(self):
        """Duplicate rollout names are rejected."""
        self.fm.create_rollout(name="test-rollout")
        with self.assertRaises(ValueError):
            self.fm.create_rollout(name="test-rollout")

    def test_promote_rollout(self):
        """Rollouts can be promoted through stages."""
        self.fm.create_rollout(name="test-rollout", stages=["canary", "staging", "production"])
        status = self.fm.promote_rollout("test-rollout")
        self.assertEqual(status.current_stage, "staging")
        status = self.fm.promote_rollout("test-rollout")
        self.assertEqual(status.current_stage, "production")

    def test_promote_at_last_stage_raises(self):
        """Promoting past the last stage raises ValueError."""
        self.fm.create_rollout(name="test-rollout", stages=["canary", "production"])
        self.fm.promote_rollout("test-rollout")  # canary -> production
        with self.assertRaises(ValueError):
            self.fm.promote_rollout("test-rollout")

    def test_complete_rollout(self):
        """Rollouts can be completed."""
        self.fm.register_target(FleetTarget(id="t1", name="T1"))
        self.fm.create_rollout(name="test-rollout")
        status = self.fm.complete_rollout("test-rollout")
        self.assertNotEqual(status.completed_at, "")
        self.assertEqual(status.targets_reached, 1)

    def test_fail_rollout_with_rollback(self):
        """Failed rollouts trigger rollback."""
        target = FleetTarget(id="t1", name="T1", policy_digest="sha256:old")
        self.fm.register_target(target)
        _ = self.fm.create_rollout(name="test-rollout")
        self.fm.update_target_status("t1", policy_digest="sha256:new")
        failed = self.fm.fail_rollout("test-rollout", reason="test failure")
        self.assertTrue(failed.failed)
        self.assertEqual(failed.failure_reason, "test failure")

    def test_fleet_health(self):
        """Fleet health returns summary metrics."""
        self.fm.register_target(FleetTarget(id="t1", name="T1", compliant=True))
        self.fm.register_target(FleetTarget(id="t2", name="T2", compliant=False))
        health = self.fm.fleet_health()
        self.assertEqual(health["total_targets"], 2)
        self.assertEqual(health["compliant_targets"], 1)
        self.assertEqual(health["non_compliant_targets"], 1)

    def test_compliance_report(self):
        """Compliance report includes per-target details."""
        self.fm.register_target(FleetTarget(id="t1", name="T1"))
        report = self.fm.compliance_report()
        self.assertIn("fleet_health", report)
        self.assertIn("targets", report)
        self.assertEqual(len(report["targets"]), 1)

    def test_update_target_status(self):
        """Target scan status can be updated."""
        self.fm.register_target(FleetTarget(id="t1", name="T1"))
        self.fm.update_target_status("t1", verdict="pass", compliant=True, policy_digest="sha256:abc")
        target = self.fm.get_target("t1")
        self.assertTrue(target.compliant)
        self.assertEqual(target.policy_digest, "sha256:abc")

    def test_update_unknown_target(self):
        """Updating an unknown target is a no-op (logged as warning)."""
        self.fm.update_target_status("unknown", verdict="pass", compliant=True)

    def test_list_rollouts(self):
        """Rollouts can be listed."""
        self.fm.create_rollout(name="rollout-1")
        self.fm.create_rollout(name="rollout-2")
        rollouts = self.fm.list_rollouts()
        self.assertEqual(len(rollouts), 2)

    def test_list_active_rollouts(self):
        """Active rollouts can be filtered."""
        self.fm.create_rollout(name="active")
        self.fm.create_rollout(name="completed")
        self.fm.complete_rollout("completed")
        active = self.fm.list_rollouts(active_only=True)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].name, "active")

    def test_get_rollout_status(self):
        """Rollout status can be retrieved."""
        self.fm.create_rollout(name="test")
        status = self.fm.get_rollout_status("test")
        self.assertIsNotNone(status)
        self.assertEqual(status.name, "test")

    def test_get_nonexistent_rollout_status(self):
        """Getting status for nonexistent rollout returns None."""
        self.assertIsNone(self.fm.get_rollout_status("nonexistent"))


if __name__ == "__main__":
    unittest.main()
