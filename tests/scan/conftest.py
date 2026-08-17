"""Shared fixtures and builders for the scan test suite.

Added in v2.1.0 (refactor). Extracts the duplicated ``_make_project``,
``_make_finding``, ``_make_scan_result``, and ``FIXTURES_DIR`` helpers
from seven+ scan test files into a single importable module so the
helpers can be shared without copy-paste drift.

Usage::

    from tests.scan.conftest import make_npm_project, make_finding, make_scan_result
    from tests.scan.conftest import FIXTURES_DIR

Or, for pytest-style fixtures (the ``scan_fixtures_dir`` fixture)::

    def test_something(scan_fixtures_dir: Path) -> None:
        ...
"""

from __future__ import annotations

import functools
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from picosentry.scan.models import (
    Confidence,
    Finding,
    ScanResult,
    ScanStats,
    Severity,
)

# ─── Path constants ────────────────────────────────────────────────────────

FIXTURES_DIR: Path = Path(__file__).parent / "fixtures"

# pytest collects this whole directory recursively by default, and tests/scan/fixtures
# holds 7000+ nested fixture dirs (~96MB). There are no test files inside — they are
# scan inputs only. Exclude them so collection doesn't walk the entire tree.
collect_ignore_glob = ["fixtures/**"]


# ─── Project builders ──────────────────────────────────────────────────────


def make_npm_project(tmp_path: Path, pkg_json: dict, files: dict | None = None) -> Path:
    """Create a minimal npm project tree at ``tmp_path``.

    Writes a ``package.json`` and any optional ``files`` mapping (relative
    path → file contents). Returns ``tmp_path`` for chaining.

    Replaces verbatim-duplicate ``_make_project`` helpers in seven scan
    test files (test_scanner, test_cli, test_engine, test_network_exfil,
    test_worm_propagation, test_obfuscation_extended, and test_cli_unit).
    The single source-of-truth eliminates drift across files.
    """
    (tmp_path / "package.json").write_text(json.dumps(pkg_json))
    if files:
        for rel, content in files.items():
            fpath = tmp_path / rel
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(content)
    return tmp_path


# ─── Model builders ────────────────────────────────────────────────────────


def make_finding(
    rule_id: str = "L2-POST-001",
    severity: Severity = Severity.HIGH,
    package: str = "evil@1.0.0",
    **overrides: Any,
) -> Finding:
    """Build a Finding with sensible defaults plus ``**overrides``.

    Converges three previously-divergent ``_make_finding`` helpers from
    test_cli_unit, test_cli_extended, and test_policy_extended onto one
    set of defaults. The ``**overrides`` escape hatch preserves any
    unusual defaults the prior helpers carried.
    """
    return Finding(
        rule_id=rule_id,
        severity=severity,
        confidence=overrides.pop("confidence", Confidence.EXACT),
        package=package,
        file=overrides.pop("file", f"{package}/package.json"),
        message=overrides.pop("message", "Post-install script"),
        evidence=overrides.pop("evidence", "scripts.postinstall"),
        remediation=overrides.pop("remediation", "Remove script"),
        **overrides,
    )


def make_scan_result(
    target: str = "/tmp/test",
    findings: list[Finding] | None = None,
    **overrides: Any,
) -> ScanResult:
    """Build a ScanResult with sensible defaults plus ``**overrides``.

    Replaces ``_make_result`` in test_cli_unit, test_cli_extended,
    test_guards, test_github, test_deterministic_output, plus three
    inline ``ScanResult(...)`` blocks in test_scanner.
    """
    return ScanResult(
        target=target,
        engine_version=overrides.pop("engine_version", "0.15.0"),
        corpus_version=overrides.pop("corpus_version", "abc123"),
        findings=findings if findings is not None else [],
        stats=overrides.pop(
            "stats",
            ScanStats(packages_scanned=1, files_scanned=10, duration_ms=50),
        ),
        **overrides,
    )


# ─── Pytest fixtures ───────────────────────────────────────────────────────


@pytest.fixture
def scan_fixtures_dir() -> Path:
    """Return the path to ``tests/scan/fixtures``.

    Replaces the six inline ``FIXTURES_DIR = Path(__file__).parent /
    "fixtures"`` definitions that previously lived in individual test
    files. Test methods that previously used the module-level constant
    should switch to this fixture for a single source of truth.
    """
    return FIXTURES_DIR


# ─── Shared CLI subprocess cache ───────────────────────────────────────────


@functools.cache
def scan_fixture_cached(fixture_name: str, extra_args: tuple[str, ...] = ()) -> subprocess.CompletedProcess:
    """Run ``picosentry scan <fixture> [args...]`` once per unique command
    per pytest-xdist worker and share the CompletedProcess.

    Fixtures are read-only scan inputs, yet several tests re-run the exact
    same command (e.g. ``scan shai_hulud --exit-code`` backs three
    action-exit-code tests); each unique run costs ~2.5s of interpreter +
    engine startup. ponytail: tests asserting *freshness* (two independent
    executions — determinism-across-runs, normal-output timestamps) must
    bypass this and call subprocess.run directly.
    """
    fixture = FIXTURES_DIR / fixture_name
    if not fixture.is_dir():
        pytest.skip(f"fixture {fixture_name} not available")
    return subprocess.run(
        [sys.executable, "-m", "picosentry", "scan", str(fixture), *extra_args],
        capture_output=True,
        text=True,
        timeout=120,
    )


@pytest.fixture(autouse=True)
def _broad_scan_workspace_root(monkeypatch) -> None:
    """Broaden the scan workspace root during tests.

    Production defaults restrict external paths (``--corpus``, ``--output``,
    etc.) to the scan target's workspace. Many existing tests write outputs to
    ``tmp_path`` while scanning fixtures under the repository, so we set the
    root to the filesystem root for the test session. Dedicated path-restriction
    tests override this explicitly.
    """
    # Allow tests to write outputs to the pytest temp directory while scanning
    # fixtures that live under the repository. The production default restricts
    # paths to the current working directory.
    monkeypatch.setenv("PICOSENTRY_SCANS_WORKSPACE_ROOT", tempfile.gettempdir())
    # Ensure the offline env is not left behind from another test.
    monkeypatch.delenv("PICOSENTRY_OFFLINE", raising=False)
