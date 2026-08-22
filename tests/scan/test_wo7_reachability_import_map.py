"""WO7-032 — _is_package_reachable rescanned entire source tree per package (O(packages x files)).

For each package, the function iterated the source tree looking for imports.
Cost scales with the product. The fix builds ONE import-map per scan (a set
of imported module roots per ecosystem, memoized on target), then checks each
package against the set in O(1): O(packages + files) instead of O(packages x files).
"""

from __future__ import annotations

import time
from pathlib import Path

from picosentry.scan.rules.advisory_check import _import_map, _import_map_cache, _is_package_reachable


def _make_source_tree(tmp_path: Path, n_files: int) -> Path:
    for i in range(n_files):
        (tmp_path / f"mod_{i}.py").write_text(f"import os\n# package pkg_{i}\n", encoding="utf-8")
    return tmp_path


class TestImportMapMemoization:
    def test_import_map_cached_per_target(self, tmp_path: Path):
        _import_map_cache.clear()
        _make_source_tree(tmp_path, 5)
        first = _import_map(tmp_path)
        second = _import_map(tmp_path)
        assert first is second, "second call must return the cached dict object (no re-walk)"

    def test_cache_cleared_between_scans(self, tmp_path: Path):
        _import_map_cache.clear()
        _make_source_tree(tmp_path, 3)
        _import_map(tmp_path)
        assert len(_import_map_cache) == 1
        _import_map_cache.clear()
        assert len(_import_map_cache) == 0


class TestReachabilityPerf:
    def test_100_packages_50_files_under_0_5s(self, tmp_path: Path):
        _import_map_cache.clear()
        project = _make_source_tree(tmp_path, 50)
        packages = [f"pkg_{i}" for i in range(100)]

        start = time.time()
        for pkg in packages:
            _is_package_reachable(project, pkg, "pypi")
        elapsed = time.time() - start

        assert elapsed < 0.5, f"100 packages x 50 files took {elapsed:.3f}s, expected <0.5s (was 2.043s pre-fix)"

    def test_tree_walked_once_for_many_packages(self, tmp_path: Path, monkeypatch):
        _import_map_cache.clear()
        project = _make_source_tree(tmp_path, 20)

        walk_count = [0]
        original_rglob = Path.rglob

        def counting_rglob(self, *args, **kwargs):
            if self == project:
                walk_count[0] += 1
            return original_rglob(self, *args, **kwargs)

        monkeypatch.setattr(Path, "rglob", counting_rglob)

        for i in range(50):
            _is_package_reachable(project, f"pkg_{i}", "pypi")

        assert walk_count[0] == 1, f"tree walked {walk_count[0]} times, expected 1 (memoized)"


class TestReachabilityBehaviorPreserved:
    def test_imported_pypi_package_is_reachable(self, tmp_path: Path):
        _import_map_cache.clear()
        (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")
        assert _is_package_reachable(tmp_path, "requests", "pypi") is True

    def test_unused_pypi_package_is_not_reachable(self, tmp_path: Path):
        _import_map_cache.clear()
        (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")
        assert _is_package_reachable(tmp_path, "requests", "pypi") is False

    def test_no_source_files_not_reachable(self, tmp_path: Path):
        _import_map_cache.clear()
        assert _is_package_reachable(tmp_path, "anything", "pypi") is False

    def test_unknown_ecosystem_defaults_reachable(self, tmp_path: Path):
        _import_map_cache.clear()
        (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")
        assert _is_package_reachable(tmp_path, "anything", "unknown-eco") is True
