"""Tests for baseline hardening (anti-poisoning)."""

import pytest

from picosentry.sandbox.baseline_hardening import (
    BaselineUpdateRateLimit,
    HardenedBaselineManager,
    SignedBaseline,
)
from picosentry.sandbox.l4.models import Baseline


@pytest.fixture
def npm_baseline():
    return Baseline(
        name="npm-install",
        package="npm",
        version="*",
        expected_network_calls=10,
        expected_dns_queries=5,
        expected_fs_ops=500,
        expected_spawns=0,
        expected_runtime_ms_range=(1000, 120000),
        allowed_domains=["registry.npmjs.org"],
        allowed_paths=["node_modules/**"],
    )


@pytest.fixture
def manager():
    return HardenedBaselineManager(signing_secret="test-secret")


class TestSignedBaseline:
    def test_sign_and_verify(self, npm_baseline):
        signed = SignedBaseline.from_baseline(npm_baseline, secret="my-secret", signer="admin")
        assert signed.verify("my-secret") is True

    def test_wrong_secret_fails(self, npm_baseline):
        signed = SignedBaseline.from_baseline(npm_baseline, secret="correct")
        assert signed.verify("wrong") is False

    def test_tampered_baseline_fails(self, npm_baseline):
        signed = SignedBaseline.from_baseline(npm_baseline, secret="secret")
        # Tamper with the baseline content
        tampered = SignedBaseline(
            baseline=Baseline(
                name="npm-install",
                package="npm",
                expected_network_calls=999,  # changed!
            ),
            signature=signed.signature,
        )
        assert tampered.verify("secret") is False

    def test_to_dict(self, npm_baseline):
        signed = SignedBaseline.from_baseline(npm_baseline, secret="s", signer="admin")
        d = signed.to_dict()
        assert "signature" in d
        assert d["signed_by"] == "admin"


class TestBaselineUpdateRateLimit:
    def test_allows_under_limit(self):
        rl = BaselineUpdateRateLimit(max_updates_per_hour=3)
        assert rl.check() is True
        rl.record()
        assert rl.check() is True

    def test_blocks_over_limit(self):
        rl = BaselineUpdateRateLimit(max_updates_per_hour=2)
        rl.record()
        rl.record()
        assert rl.check() is False


class TestHardenedBaselineManager:
    def test_sign_and_verify(self, manager, npm_baseline):
        signed = manager.sign(npm_baseline, signer="admin")
        assert manager.verify(signed) is True

    def test_first_update_allowed(self, manager, npm_baseline):
        check = manager.check_update_allowed("npm-install", npm_baseline)
        assert check.allowed is True

    def test_normal_update_allowed(self, manager, npm_baseline):
        manager.apply_update("npm-install", npm_baseline)
        slightly_changed = Baseline(
            name="npm-install",
            package="npm",
            expected_network_calls=12,  # small change
            expected_dns_queries=5,
            expected_fs_ops=500,
            expected_runtime_ms_range=(1000, 120000),
        )
        check = manager.check_update_allowed("npm-install", slightly_changed)
        assert check.allowed is True

    def test_extreme_drift_blocked(self, manager, npm_baseline):
        manager.apply_update("npm-install", npm_baseline)
        extreme = Baseline(
            name="npm-install",
            package="npm",
            expected_network_calls=1000,  # 100x change
            expected_dns_queries=500,
            expected_fs_ops=50000,
            expected_spawns=50,
            expected_runtime_ms_range=(1, 999999),
        )
        check = manager.check_update_allowed("npm-install", extreme)
        assert check.allowed is False
