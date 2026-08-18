"""WO5.0.0-027 item 8 — packages_scanned must count venv/ and .tox/ layouts.

count_installed_packages globbed only .venv while detection and the rule layer
(scan/rules/pypi_utils._find_site_packages_dirs) support venv/, .tox/ and
friends — plain-venv projects reported packages_scanned: 0.
"""

from __future__ import annotations

from pathlib import Path

from picosentry.scan._engine_scan_helpers import count_installed_packages


def _make_site_packages(root: Path, *names: str) -> Path:
    sp = root / "lib" / "python3.11" / "site-packages"
    sp.mkdir(parents=True, exist_ok=True)
    for name in names:
        (sp / name).mkdir()
    return sp


def test_plain_venv_layout_counted(tmp_path):
    _make_site_packages(tmp_path / "venv", "requests-2.31.0.dist-info", "flask-3.0.0.dist-info")
    assert count_installed_packages(tmp_path) == 2


def test_tox_layout_counted(tmp_path):
    _make_site_packages(tmp_path / ".tox" / "py310", "requests-2.31.0.dist-info")
    assert count_installed_packages(tmp_path) == 1


def test_multi_layout_dedupes_same_version(tmp_path):
    _make_site_packages(tmp_path / "venv", "requests-2.31.0.dist-info")
    _make_site_packages(tmp_path / ".tox" / "py310", "requests-2.31.0.dist-info")
    assert count_installed_packages(tmp_path) == 1


def test_dot_venv_still_counted(tmp_path):
    _make_site_packages(tmp_path / ".venv", "requests-2.31.0.dist-info")
    assert count_installed_packages(tmp_path) == 1


def test_engine_scan_reports_packages_for_venv_project(tmp_path):
    from picosentry.scan.engine import create_default_engine

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0.1.0"\n')
    _make_site_packages(tmp_path / "venv", "requests-2.31.0.dist-info")
    result = create_default_engine().scan(tmp_path)
    assert result.stats.packages_scanned == 1
