"""
test_realistic_fixtures.py — Regression tests against realistic npm project fixtures.

These tests validate that PicoSentry handles real-world project structures:
- Projects with package-lock.json (npm v3 lockfile)
- Projects with node_modules containing multiple packages
- Projects with postinstall scripts
- Projects with lockfile drift (deps in lockfile not in manifest)
- Multi-severity findings across many rules
- Deterministic output across different run orders
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from picosentry.scan.engine import create_default_engine
from picosentry.scan.models import ScanResult

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PICOSENTRY = [sys.executable, "-m", "picosentry"]


class TestRealisticNpmProject:
    """Test against a realistic npm project with lockfile and node_modules."""

    @pytest.fixture
    def fixture_path(self):
        path = FIXTURES_DIR / "realistic_npm"
        if not path.is_dir():
            pytest.skip("realistic_npm fixture not available")
        return path

    def test_scan_finds_post_install(self, fixture_path):
        """Realistic project with postinstall script must be flagged."""
        engine = create_default_engine()
        result = engine.scan(str(fixture_path))
        post_install = [f for f in result.findings if f.rule_id == "L2-POST-001"]
        assert len(post_install) > 0, "Should detect postinstall script"
        assert post_install[0].severity.value in ("HIGH", "CRITICAL")

    def test_scan_finds_lockfile_drift(self, fixture_path):
        """Dev deps in lockfile but not installed = lockfile drift."""
        engine = create_default_engine()
        result = engine.scan(str(fixture_path))
        lock_drift = [f for f in result.findings if f.rule_id == "L2-LOCK-001"]
        assert len(lock_drift) > 0, "Should detect lockfile drift for devDependencies"

    def test_scan_finds_manifest_optional_deps(self, fixture_path):
        """Project with optionalDependencies triggering L2-MANI-002."""
        engine = create_default_engine()
        result = engine.scan(str(fixture_path))
        manifest = [f for f in result.findings if f.rule_id == "L2-MANI-002"]
        assert len(manifest) > 0, "Should detect optionalDependencies with scripts"

    def test_deterministic_output_across_runs(self, fixture_path):
        """Two scans of realistic project must produce byte-identical JSON with --deterministic-output."""
        result = subprocess.run(
            PICOSENTRY + ["scan", str(fixture_path), "--format", "json", "--deterministic-output"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)

        result2 = subprocess.run(
            PICOSENTRY + ["scan", str(fixture_path), "--format", "json", "--deterministic-output"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result2.returncode == 0
        data2 = json.loads(result2.stdout)

        assert data == data2, "Two scans must produce identical deterministic output"

    def test_json_output_sorted_keys(self, fixture_path):
        """JSON output must have sorted top-level keys."""
        result = subprocess.run(
            PICOSENTRY + ["scan", str(fixture_path), "--format", "json", "--deterministic-output"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        keys = list(data.keys())
        assert keys == sorted(keys), f"Keys not sorted: {keys}"

    def test_multi_severity_findings(self, fixture_path):
        """Realistic project should have findings at multiple severity levels."""
        engine = create_default_engine()
        result = engine.scan(str(fixture_path))
        severities = {f.severity.value for f in result.findings}
        assert len(severities) >= 2, f"Expected 2+ severity levels, got: {severities}"
        assert "HIGH" in severities, "Should have HIGH findings"

    def test_fail_on_high_exits_nonzero(self, fixture_path):
        """--fail-on high should exit nonzero on project with HIGH findings."""
        result = subprocess.run(
            PICOSENTRY + ["scan", str(fixture_path), "--fail-on", "high"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 1, (
            f"--fail-on high should exit 1 on project with HIGH findings, got {result.returncode}"
        )

    def test_fail_on_critical_exits_zero(self, fixture_path):
        """--fail-on critical should exit 0 if no CRITICAL findings."""
        result = subprocess.run(
            PICOSENTRY + ["scan", str(fixture_path), "--fail-on", "critical"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"--fail-on critical should exit 0 (no CRITICAL findings), got {result.returncode}"
        )

    def test_verify_determinism_passes(self, fixture_path):
        """--verify-determinism should pass on realistic project."""
        result = subprocess.run(
            PICOSENTRY + ["scan", str(fixture_path), "--verify-determinism"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, (
            f"--verify-determinism should pass, got exit {result.returncode}. stderr: {result.stderr}"
        )

    def test_no_audit_in_deterministic_output(self, fixture_path):
        """--deterministic-output must not include audit timestamps."""
        result = subprocess.run(
            PICOSENTRY + ["scan", str(fixture_path), "--format", "json", "--deterministic-output"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "audit" not in data, "Deterministic output must not include audit"
        assert "duration_ms" not in data.get("stats", {}), "Deterministic output must not include duration_ms"

    def test_normal_output_includes_audit(self, fixture_path):
        """Normal JSON output must include audit timestamps."""
        result = subprocess.run(
            PICOSENTRY + ["scan", str(fixture_path), "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "audit" in data, "Normal output must include audit section"
        assert "started_at" in data["audit"], "Audit must include started_at"
        assert "completed_at" in data["audit"], "Audit must include completed_at"


class TestExistingFixturesSmokeTest:
    """Quick smoke test that all existing fixtures scan without errors."""

    @pytest.fixture(
        params=[
            "clean_project",
            "colors_js",
            "crossenv",
            "event_stream",
            "left_pad",
            "nx_typosquat",
            "pnpm_dangerous",
            "pnpm_no_npmrc",
            "shai_hulud",
            "ua_parser_js",
            "realistic_npm",
        ]
    )
    def fixture_name(self, request):
        return request.param

    def test_fixture_scans_cleanly(self, fixture_name):
        """Every fixture must scan without errors or crashes."""
        fixture = FIXTURES_DIR / fixture_name
        if not fixture.is_dir():
            pytest.skip(f"fixture {fixture_name} not available")

        engine = create_default_engine()
        result = engine.scan(str(fixture))
        assert isinstance(result, ScanResult)
        assert result.engine_version, "Should have engine_version"
        assert result.corpus_version, "Should have corpus_version"
        assert result.scan_id, "Should have scan_id"

    def test_fixture_json_output_valid(self, fixture_name):
        """Every fixture must produce valid JSON output."""
        fixture = FIXTURES_DIR / fixture_name
        if not fixture.is_dir():
            pytest.skip(f"fixture {fixture_name} not available")

        result = subprocess.run(
            PICOSENTRY + ["scan", str(fixture), "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "findings" in data
        assert "scan_id" in data
        assert "corpus_version" in data
        assert "engine_version" in data