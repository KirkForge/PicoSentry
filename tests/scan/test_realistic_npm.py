"""Regression tests against the realistic npm project fixture — moved from
test_realistic_fixtures.py (smoke sibling: test_realistic_smoke.py) so
pytest-xdist --dist=loadfile can balance the ~68s file across workers.
Bodies unchanged.
"""

import json
import subprocess
import sys

import pytest

from picosentry.scan.engine import create_default_engine

from tests.scan.conftest import FIXTURES_DIR, scan_fixture_cached

PICOSENTRY = [sys.executable, "-m", "picosentry"]


def _scan(fixture_name: str, extra_args: list[str] | None = None) -> subprocess.CompletedProcess:
    """Cached CLI run — see scan_fixture_cached in tests/scan/conftest.py."""
    return scan_fixture_cached(fixture_name, tuple(extra_args or ()))


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
        result = subprocess.run(  # fresh run #1 — do not cache: assertion is run1 == run2
            [*PICOSENTRY, "scan", str(fixture_path), "--format", "json", "--deterministic-output"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)

        result2 = subprocess.run(  # fresh run #2
            [*PICOSENTRY, "scan", str(fixture_path), "--format", "json", "--deterministic-output"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result2.returncode == 0
        data2 = json.loads(result2.stdout)

        assert data == data2, "Two scans must produce identical deterministic output"

    def test_json_output_sorted_keys(self, fixture_path):
        """JSON output must have sorted top-level keys."""
        result = _scan("realistic_npm", ["--format", "json", "--deterministic-output"])
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
        result = _scan("realistic_npm", ["--fail-on", "high"])
        assert result.returncode == 1, (
            f"--fail-on high should exit 1 on project with HIGH findings, got {result.returncode}"
        )

    def test_fail_on_critical_exits_zero(self, fixture_path):
        """--fail-on critical should exit 0 if no CRITICAL findings."""
        result = _scan("realistic_npm", ["--fail-on", "critical"])
        assert result.returncode == 0, (
            f"--fail-on critical should exit 0 (no CRITICAL findings), got {result.returncode}"
        )

    def test_verify_determinism_passes(self, fixture_path):
        """--verify-determinism should pass on realistic project."""
        result = _scan("realistic_npm", ["--verify-determinism"])
        assert result.returncode == 0, (
            f"--verify-determinism should pass, got exit {result.returncode}. stderr: {result.stderr}"
        )

    def test_no_audit_in_deterministic_output(self, fixture_path):
        """--deterministic-output must not include audit timestamps."""
        result = _scan("realistic_npm", ["--format", "json", "--deterministic-output"])
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "audit" not in data, "Deterministic output must not include audit"
        assert "duration_ms" not in data.get("stats", {}), "Deterministic output must not include duration_ms"

    def test_normal_output_includes_audit(self, fixture_path):
        """Normal JSON output must include audit timestamps."""
        result = _scan("realistic_npm", ["--format", "json"])
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "audit" in data, "Normal output must include audit section"
        assert "started_at" in data["audit"], "Audit must include started_at"
        assert "completed_at" in data["audit"], "Audit must include completed_at"
