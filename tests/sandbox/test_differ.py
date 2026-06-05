"""Tests for L4 differ — comparing profiles against baselines."""

from picosentry.sandbox.l4.baseline import load_all_baselines, load_baseline
from picosentry.sandbox.l4.differ import compare_profile_to_baseline, find_best_baseline
from picosentry.sandbox.l4.models import (
    Baseline,
    BehavioralProfile,
    DnsQuery,
    DriftResult,
    FileOperation,
    NetworkCall,
    ProcessSpawn,
)

# ─── Clean profile vs baseline ────────────────────────────────────────────────


class TestCleanVsBaseline:
    def test_clean_python_profile(self, clean_profile, python_baseline):
        drift = compare_profile_to_baseline(clean_profile, python_baseline)
        assert drift.score == 0.0
        assert drift.network_drift is False
        assert drift.dns_drift is False
        assert drift.fs_drift is False
        assert drift.spawn_drift is False
        assert drift.timing_drift is False

    def test_clean_npm_profile(self):
        profile = BehavioralProfile(
            package="npm",
            network_calls=[],
            dns_queries=[],
            fs_ops=[],
            spawns=[],
            total_runtime_ms=5000,
        )
        baseline = load_baseline("npm-install")
        drift = compare_profile_to_baseline(profile, baseline)
        assert drift.score == 0.0

    def test_empty_profile_vs_baseline(self, python_baseline):
        profile = BehavioralProfile(package="python", total_runtime_ms=100)
        drift = compare_profile_to_baseline(profile, python_baseline)
        assert drift.score == 0.0


# ─── Network drift ────────────────────────────────────────────────────────────


class TestNetworkDrift:
    def test_network_drift_detected(self, python_baseline):
        profile = BehavioralProfile(
            package="python",
            network_calls=[NetworkCall(address="evil.com", port=443)],
            total_runtime_ms=100,
        )
        drift = compare_profile_to_baseline(profile, python_baseline)
        assert drift.network_drift is True
        assert drift.score > 0.0

    def test_multiple_network_calls(self, python_baseline):
        profile = BehavioralProfile(
            package="python",
            network_calls=[
                NetworkCall(address="evil1.com"),
                NetworkCall(address="evil2.com"),
                NetworkCall(address="evil3.com"),
            ],
            total_runtime_ms=100,
        )
        drift = compare_profile_to_baseline(profile, python_baseline)
        assert drift.network_drift is True

    def test_npm_allows_network(self):
        baseline = load_baseline("npm-install")
        profile = BehavioralProfile(
            package="npm",
            network_calls=[NetworkCall(address="registry.npmjs.org")],
            dns_queries=[DnsQuery(hostname="registry.npmjs.org")],
            total_runtime_ms=5000,
        )
        # npm baseline expects 10 network calls, so 1 is fine
        drift = compare_profile_to_baseline(profile, baseline)
        assert drift.network_drift is False


# ─── DNS drift ─────────────────────────────────────────────────────────────────


class TestDnsDrift:
    def test_dns_drift_detected(self, python_baseline):
        profile = BehavioralProfile(
            package="python",
            dns_queries=[DnsQuery(hostname="evil.com")],
            total_runtime_ms=100,
        )
        drift = compare_profile_to_baseline(profile, python_baseline)
        assert drift.dns_drift is True

    def test_no_dns_drift_when_within_bounds(self):
        baseline = load_baseline("npm-install")
        profile = BehavioralProfile(
            package="npm",
            dns_queries=[DnsQuery(hostname="registry.npmjs.org")],
            total_runtime_ms=5000,
        )
        drift = compare_profile_to_baseline(profile, baseline)
        assert drift.dns_drift is False


# ─── FS drift ──────────────────────────────────────────────────────────────────


class TestFsDrift:
    def test_fs_drift_detected(self, python_baseline):
        # python-script expects <= 100 fs ops
        ops = [FileOperation(path=f"/tmp/file{i}", operation="write") for i in range(101)]
        profile = BehavioralProfile(
            package="python",
            fs_ops=ops,
            total_runtime_ms=100,
        )
        drift = compare_profile_to_baseline(profile, python_baseline)
        assert drift.fs_drift is True

    def test_no_fs_drift_within_bounds(self, python_baseline):
        profile = BehavioralProfile(
            package="python",
            fs_ops=[FileOperation(path="/tmp/file1", operation="read")],
            total_runtime_ms=100,
        )
        drift = compare_profile_to_baseline(profile, python_baseline)
        assert drift.fs_drift is False


# ─── Spawn drift ───────────────────────────────────────────────────────────────


class TestSpawnDrift:
    def test_spawn_drift_detected(self, python_baseline):
        profile = BehavioralProfile(
            package="python",
            spawns=[ProcessSpawn(executable="/bin/bash")],
            total_runtime_ms=100,
        )
        drift = compare_profile_to_baseline(profile, python_baseline)
        assert drift.spawn_drift is True

    def test_no_spawn_drift(self, python_baseline):
        profile = BehavioralProfile(
            package="python",
            spawns=[],
            total_runtime_ms=100,
        )
        drift = compare_profile_to_baseline(profile, python_baseline)
        assert drift.spawn_drift is False


# ─── Timing drift ─────────────────────────────────────────────────────────────


class TestTimingDrift:
    def test_timing_drift_slow(self, python_baseline):
        # python-script expects 10-30000ms
        profile = BehavioralProfile(
            package="python",
            total_runtime_ms=60000,  # Way over the range
        )
        drift = compare_profile_to_baseline(profile, python_baseline)
        assert drift.timing_drift is True

    def test_timing_drift_fast(self, python_baseline):
        # python-script expects 10-30000ms
        profile = BehavioralProfile(
            package="python",
            total_runtime_ms=1,  # Way under the range
        )
        drift = compare_profile_to_baseline(profile, python_baseline)
        assert drift.timing_drift is True

    def test_no_timing_drift_within_range(self, python_baseline):
        profile = BehavioralProfile(
            package="python",
            total_runtime_ms=500,  # Within 10-30000ms
        )
        drift = compare_profile_to_baseline(profile, python_baseline)
        assert drift.timing_drift is False


# ─── Domain checks ────────────────────────────────────────────────────────────


class TestDomainChecks:
    def test_unexpected_domain_detected(self):
        baseline = Baseline(
            name="strict-domain",
            package="myapp",
            expected_network_calls=5,
            expected_dns_queries=2,
            allowed_domains=["api.myapp.com"],
        )
        profile = BehavioralProfile(
            package="myapp",
            network_calls=[NetworkCall(address="evil.com")],
            total_runtime_ms=100,
        )
        drift = compare_profile_to_baseline(profile, baseline)
        assert drift.network_drift is True

    def test_allowed_domain_passes(self):
        baseline = Baseline(
            name="strict-domain",
            package="myapp",
            expected_network_calls=5,
            expected_dns_queries=2,
            allowed_domains=["api.myapp.com"],
        )
        profile = BehavioralProfile(
            package="myapp",
            network_calls=[NetworkCall(address="api.myapp.com")],
            total_runtime_ms=100,
        )
        # Network calls within limit and domain is allowed
        drift = compare_profile_to_baseline(profile, baseline)
        assert drift.network_drift is False

    def test_wildcard_domain_passes(self):
        baseline = Baseline(
            name="wildcard-domain",
            package="myapp",
            expected_network_calls=5,
            allowed_domains=["*"],
        )
        profile = BehavioralProfile(
            package="myapp",
            network_calls=[NetworkCall(address="anything.com")],
            total_runtime_ms=100,
        )
        drift = compare_profile_to_baseline(profile, baseline)
        assert drift.network_drift is False


# ─── Path checks ───────────────────────────────────────────────────────────────


class TestPathChecks:
    def test_unexpected_path_detected(self):
        baseline = Baseline(
            name="strict-path",
            package="myapp",
            expected_fs_ops=100,
            allowed_paths=["/tmp/**", "/var/lib/myapp/**"],
        )
        profile = BehavioralProfile(
            package="myapp",
            fs_ops=[FileOperation(path="/etc/passwd", operation="read")],
            total_runtime_ms=100,
        )
        drift = compare_profile_to_baseline(profile, baseline)
        assert drift.fs_drift is True

    def test_allowed_path_passes(self):
        baseline = Baseline(
            name="strict-path",
            package="myapp",
            expected_fs_ops=100,
            allowed_paths=["/tmp/**"],
        )
        profile = BehavioralProfile(
            package="myapp",
            fs_ops=[FileOperation(path="/tmp/test.log", operation="write")],
            total_runtime_ms=100,
        )
        drift = compare_profile_to_baseline(profile, baseline)
        assert drift.fs_drift is False

    def test_wildcard_path_passes(self):
        baseline = Baseline(
            name="wildcard-path",
            package="myapp",
            expected_fs_ops=100,
            allowed_paths=["**"],
        )
        profile = BehavioralProfile(
            package="myapp",
            fs_ops=[FileOperation(path="/etc/passwd", operation="read")],
            total_runtime_ms=100,
        )
        drift = compare_profile_to_baseline(profile, baseline)
        assert drift.fs_drift is False


# ─── find_best_baseline ────────────────────────────────────────────────────────


class TestFindBestBaseline:
    def test_matches_python_package(self, clean_profile):
        baselines = load_all_baselines()
        result = find_best_baseline(clean_profile, baselines)
        assert result is not None
        baseline, _drift = result
        assert baseline.package == "python"

    def test_matches_npm_package(self):
        profile = BehavioralProfile(package="npm", total_runtime_ms=5000)
        baselines = load_all_baselines()
        result = find_best_baseline(profile, baselines)
        assert result is not None
        assert result[0].package == "npm"

    def test_no_matching_baseline(self):
        profile = BehavioralProfile(package="unknown-package-xyz", total_runtime_ms=100)
        baselines = load_all_baselines()
        result = find_best_baseline(profile, baselines)
        assert result is None

    def test_wildcard_package_matches(self):
        """Baselines with version='*' should match any version of the package."""
        baselines = load_all_baselines()
        profile = BehavioralProfile(package="python", total_runtime_ms=100)
        result = find_best_baseline(profile, baselines)
        assert result is not None

    def test_best_baseline_lowest_drift(self, clean_profile):
        """When multiple baselines match, the one with lowest drift should be selected."""
        baselines = {
            "good-match": Baseline(
                name="good-match",
                package="python",
                expected_network_calls=0,
                expected_dns_queries=0,
                expected_fs_ops=100,
                expected_spawns=0,
                expected_runtime_ms_range=(10, 30000),
            ),
            "bad-match": Baseline(
                name="bad-match",
                package="python",
                expected_network_calls=0,
                expected_dns_queries=0,
                expected_fs_ops=100,
                expected_spawns=0,
                expected_runtime_ms_range=(100000, 200000),
            ),
        }
        result = find_best_baseline(clean_profile, baselines)
        assert result is not None
        assert result[0].name == "good-match"


# ─── DriftResult ───────────────────────────────────────────────────────────────


class TestDriftResult:
    def test_drift_result_creation(self):
        drift = DriftResult(
            baseline_name="test",
            score=0.4,
            network_drift=True,
            details="Network drift",
        )
        assert drift.baseline_name == "test"
        assert drift.score == 0.4
        assert drift.network_drift is True

    def test_drift_result_to_dict(self):
        drift = DriftResult(
            baseline_name="test",
            score=0.6,
            network_drift=True,
            dns_drift=True,
            fs_drift=False,
            details="Multiple drift",
        )
        d = drift.to_dict()
        assert d["baseline_name"] == "test"
        assert d["score"] == 0.6
        assert d["network_drift"] is True
        assert d["dns_drift"] is True
        assert d["fs_drift"] is False
