"""WO7-011 — cache blind to ecosystem detection.

Empty ecosystem marker dirs (.venv, .tox) flip ecosystem detection but the
detection result was not part of the cache key. A scan with no pypi marker
cached an empty no-pypi-rules verdict; after a .venv was added (pypi
detected), the stale cache row survived. The fix folds the detected
ecosystem set into the cache key.
"""

from __future__ import annotations

import os
from pathlib import Path

from picosentry.scan.cli_service import _hash_target_inputs


class TestEcosystemHash:
    def test_empty_dir_returns_empty(self, tmp_path: Path):
        assert _hash_target_inputs(tmp_path) == ""

    def test_venv_dir_adds_ecosystem_to_hash(self, tmp_path: Path):
        h_before = _hash_target_inputs(tmp_path)
        assert h_before == ""
        os.makedirs(tmp_path / ".venv")
        h_after = _hash_target_inputs(tmp_path)
        assert h_after != "", ".venv marker must produce a non-empty ecosystem hash"
        assert h_before != h_after

    def test_tox_dir_adds_ecosystem_to_hash(self, tmp_path: Path):
        h_before = _hash_target_inputs(tmp_path)
        assert h_before == ""
        os.makedirs(tmp_path / ".tox")
        h_after = _hash_target_inputs(tmp_path)
        assert h_after != ""
        assert h_before != h_after

    def test_different_ecosystems_different_hash(self, tmp_path: Path):
        os.makedirs(tmp_path / ".venv")
        h_pypi = _hash_target_inputs(tmp_path)
        tmp_path2 = Path(os.path.join(tmp_path, "..", "alt"))
        os.makedirs(tmp_path2 / "node_modules")
        h_npm = _hash_target_inputs(tmp_path2)
        assert h_pypi != h_npm

    def test_ecosystem_change_invalidates_cache(self, tmp_path: Path):
        # Scan 1: no .venv → no pypi → hash ""
        h1 = _hash_target_inputs(tmp_path)
        assert h1 == ""

        # Scan 2: .venv added → pypi detected → different hash
        os.makedirs(tmp_path / ".venv")
        h2 = _hash_target_inputs(tmp_path)
        assert h2 != h1
        assert h2 != ""

    def test_content_change_still_invalidates(self, tmp_path: Path):
        os.makedirs(tmp_path / ".venv")
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'\n")
        h1 = _hash_target_inputs(tmp_path)
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'changed'\n")
        h2 = _hash_target_inputs(tmp_path)
        assert h1 != h2
