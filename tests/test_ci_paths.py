"""Guards for the CI path-filter regexes (WO4.0.0-017).

The ``changes`` job in .github/workflows/ci.yml classifies a PR diff so the
pytest/type-check/cli jobs can skip on docs-only changes. The regexes live
inline in the workflow; an edit that drops a path (scripts/, Dockerfile,
deploy/, ...) silently re-opens the hole where a breaking change skips CI
entirely and surfaces only post-merge. These tests pin the classification.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _ci_filter(name: str) -> re.Pattern[str]:
    text = (_REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text()
    match = re.search(rf"{name}='([^']+)'", text)
    assert match, f"ci.yml no longer defines the {name!r} filter regex"
    return re.compile(match.group(1))


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        # runtime- and test-behavior-bearing trees
        ("picosentry/scan/foo.py", True),
        ("picosentry/__init__.py", True),
        ("tests/serve/test_x.py", True),
        # the test/CI machinery itself
        ("scripts/test.sh", True),
        ("scripts/verify_release.py", True),
        ("scripts/render_benchmarks.py", True),
        # packaging + deploy surfaces
        ("pyproject.toml", True),
        ("uv.lock", True),
        ("Dockerfile", True),
        ("docker-bake.hcl", True),
        ("deploy/helm/picodome/Chart.yaml", True),
        ("deploy/kubernetes/deployment.yaml", True),
        ("action.yml", True),
        (".github/workflows/ci.yml", True),
        (".github/workflows/release.yml", True),
        # docs-only must keep skipping the pytest jobs
        ("README.md", False),
        ("CHANGELOG.md", False),
        ("docs/docker.md", False),
        ("docs/workorders/WO4.0.0-017-ci-tiers-versions.md", False),
    ],
)
def test_code_filter_classifies_paths(path: str, expected: bool) -> None:
    assert bool(_ci_filter("code_re").search(path)) is expected, path


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("picosentry/scan/models.py", True),
        ("picosentry/_core/models.py", True),
        ("tests/scan/test_scanner.py", True),
        ("scripts/render_benchmarks.py", True),
        ("pyproject.toml", True),
        # non-scan code cannot drift REPORT.json / BENCHMARKS.md
        ("picosentry/watch/types.py", False),
        ("tests/serve/test_x.py", False),
        ("scripts/test.sh", False),
        ("Dockerfile", False),
    ],
)
def test_scan_filter_classifies_paths(path: str, expected: bool) -> None:
    assert bool(_ci_filter("scan_re").search(path)) is expected, path
