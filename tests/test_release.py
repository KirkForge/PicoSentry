"""Version-drift guards.

PicoSentry has historically had version strings drift between the top-level
package, the per-subpackage __init__.py files, the wheel metadata, and the
Helm chart.  This module asserts they stay in lockstep so a release can't
ship with a stale subpackage version again.

The source of truth is the ``[project] version`` field in ``pyproject.toml``.
Every other place a version string is published must match it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import picosentry
from picosentry import _core, sandbox, scan, watch
from picosentry.serve.config import version as serve_version


def _read_pyproject_version() -> str:
    text = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
    # [project] may have other fields (name, description, ...) before the
    # version line; match within the [project] block only.
    block = re.search(r"^\[project\](?P<body>.*?)(?=^\[)", text, re.MULTILINE | re.DOTALL)
    if not block:
        raise AssertionError("pyproject.toml is missing a [project] table")
    match = re.search(r'^version\s*=\s*"([^"]+)"', block.group("body"), re.MULTILINE)
    if not match:
        raise AssertionError("pyproject.toml [project] table is missing a version field")
    return match.group(1)


def test_top_level_version_is_set() -> None:
    """The top-level version is the source of truth; must be non-empty."""
    assert picosentry.__version__
    assert isinstance(picosentry.__version__, str)


def test_subpackage_versions_match_top_level() -> None:
    """Every per-subpackage __version__ must equal the top-level version.

    Drift here is what produced the v2.0.12 release with scan/watch still
    reporting v2.0.9.  ``serve`` carries its version one level deeper than
    the others (``picosentry.serve.config.version.__version__``) — that
    module is the one to keep in lockstep.
    """
    expected = picosentry.__version__
    for name, module in [
        ("_core", _core),
        ("scan", scan),
        ("watch", watch),
        ("sandbox", sandbox),
        ("serve.config.version", serve_version),
    ]:
        actual = getattr(module, "__version__", None)
        assert actual == expected, (
            f"picosentry.{name}.__version__ = {actual!r}, expected {expected!r} (top-level picosentry.__version__)"
        )


def test_pyproject_version_matches_top_level() -> None:
    """The wheel's [project] version must equal the runtime version."""
    assert _read_pyproject_version() == picosentry.__version__


def test_helm_chart_app_version_matches() -> None:
    """The Helm chart's appVersion must equal the package version.

    The chart's own ``version`` (chart release) is allowed to lag — that
    field tracks chart-template revisions, not the app inside the chart.
    """
    expected = picosentry.__version__
    chart = Path(__file__).resolve().parent.parent / "deploy" / "helm" / "picodome" / "Chart.yaml"
    if not chart.exists():
        pytest.skip(f"Helm chart not present: {chart}")
    text = chart.read_text()
    match = re.search(r'^appVersion:\s*"([^"]+)"', text, re.MULTILINE)
    assert match, f"Helm chart is missing an appVersion field: {chart}"
    assert match.group(1) == expected, f"Helm chart appVersion = {match.group(1)!r}, expected {expected!r}"
