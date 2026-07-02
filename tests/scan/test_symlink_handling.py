"""Symlink handling in scan targets.

The engine must not follow symlinks when scanning to prevent traversal
outside the intended target directory. This is gap #18 from the audit.
"""

from pathlib import Path

from picosentry.scan.engine import create_default_engine


def _make_npm_project(path: Path) -> Path:
    project = path / "real_project"
    project.mkdir(parents=True)
    (project / "package.json").write_text('{"name": "real", "version": "1.0.0"}')
    return project


class TestSymlinkRejection:
    """Scanning a symlinked directory is rejected."""

    def test_scan_rejects_symlinked_directory(self, tmp_path: Path) -> None:
        real_project = _make_npm_project(tmp_path)
        link = tmp_path / "linked_project"
        link.symlink_to(real_project)

        engine = create_default_engine()
        result = engine.scan(link)

        assert result.findings == []
        # The scan should short-circuit and record the symlink path, not the
        # directory it points to.
        assert result.target == str(link)

    def test_scan_rejects_symlink_loop(self, tmp_path: Path) -> None:
        loop_a = tmp_path / "loop_a"
        loop_b = tmp_path / "loop_b"
        loop_a.symlink_to(loop_b)
        loop_b.symlink_to(loop_a)

        engine = create_default_engine()
        result = engine.scan(loop_a)

        assert result.findings == []
