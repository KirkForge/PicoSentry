"""Smoke scans over every existing fixture project — moved from
test_realistic_fixtures.py (npm sibling: test_realistic_npm.py) so
pytest-xdist --dist=loadfile can balance the ~68s file across workers.
Bodies unchanged.
"""

import json
import subprocess
import sys

import pytest

from picosentry.scan.engine import create_default_engine
from picosentry.scan.models import ScanResult

from tests.scan.conftest import FIXTURES_DIR

PICOSENTRY = [sys.executable, "-m", "picosentry"]


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
            [*PICOSENTRY, "scan", str(fixture), "--format", "json"],
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
