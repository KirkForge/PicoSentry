"""Tests for workspace module — project discovery, scanning, aggregation."""

import sys
import tempfile
import unittest
from pathlib import Path

from picosentry.scan.workspace import (
    NPM_MANIFEST_GLOBS,
    SKIP_DIRS,
    WorkspaceResult,
    discover_pnpm_workspace,
    discover_projects,
)


class TestDiscoverProjects(unittest.TestCase):
    """Test project discovery in directory trees."""

    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = discover_projects(Path(tmp))
            self.assertEqual(result, [])

    def test_nonexistent_directory(self):
        result = discover_projects(Path("/nonexistent/path"))
        self.assertEqual(result, [])

    def test_single_package_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text('{"name": "test"}')
            result = discover_projects(Path(tmp))
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].name, Path(tmp).name)

    def test_nested_package_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"name": "root"}')
            sub = root / "packages" / "lib"
            sub.mkdir(parents=True)
            (sub / "package.json").write_text('{"name": "lib"}')
            result = discover_projects(root)
            self.assertEqual(len(result), 2)

    def test_skips_node_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"name": "root"}')
            nm = root / "node_modules" / "dep"
            nm.mkdir(parents=True)
            (nm / "package.json").write_text('{"name": "dep"}')
            result = discover_projects(root)
            # Should find root but not node_modules
            self.assertEqual(len(result), 1)

    def test_skips_dot_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"name": "root"}')
            dot = root / ".hidden" / "project"
            dot.mkdir(parents=True)
            (dot / "package.json").write_text('{"name": "hidden"}')
            result = discover_projects(root)
            self.assertEqual(len(result), 1)

    def test_skips_git_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"name": "root"}')
            git = root / ".git"
            git.mkdir()
            (git / "package.json").write_text('{"name": "git-pkg"}')
            result = discover_projects(root)
            self.assertEqual(len(result), 1)

    def test_resolves_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"name": "root"}')
            # Symlinks are skipped
            link = root / "linked"
            target = root / "target"
            target.mkdir()
            (target / "package.json").write_text('{"name": "target"}')
            try:
                link.symlink_to(target)
                result = discover_projects(root)
                # Should find root + target but NOT follow symlink
                self.assertGreaterEqual(len(result), 1)
            except OSError:
                pass  # Skip on platforms without symlink support

    def test_permission_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"name": "root"}')
            restricted = root / "restricted"
            restricted.mkdir()
            (restricted / "package.json").write_text('{"name": "restricted"}')
            restricted.chmod(0o000)
            result = discover_projects(root)
            # Should find at least root
            self.assertGreaterEqual(len(result), 1)
            restricted.chmod(0o755)  # Restore for cleanup

    def test_max_depth(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"name": "root"}')
            deep = root / "a" / "b" / "c" / "d" / "e" / "f" / "g" / "h" / "i"
            deep.mkdir(parents=True)
            (deep / "package.json").write_text('{"name": "deep"}')
            result = discover_projects(root, max_depth=3)
            # Should find root but not deep (depth > 3)
            self.assertEqual(len(result), 1)

    def test_lockfile_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"name": "root"}')
            sub = root / "packages" / "lib"
            sub.mkdir(parents=True)
            (sub / "package.json").write_text('{"name": "lib"}')
            (sub / "pnpm-lock.yaml").write_text("packages: []")
            result = discover_projects(root)
            self.assertEqual(len(result), 2)


class TestDiscoverPnpmWorkspace(unittest.TestCase):
    """Test pnpm workspace discovery."""

    def test_no_workspace_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text('{"name": "test"}')
            result = discover_pnpm_workspace(Path(tmp))
            self.assertGreaterEqual(len(result), 1)

    def test_with_workspace_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"name": "root"}')
            (root / "pnpm-workspace.yaml").write_text("packages:\n  - 'packages/*'\n")
            pkg = root / "packages" / "lib"
            pkg.mkdir(parents=True)
            (pkg / "package.json").write_text('{"name": "lib"}')
            result = discover_pnpm_workspace(root)
            self.assertGreaterEqual(len(result), 1)

    def test_empty_packages_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"name": "root"}')
            (root / "pnpm-workspace.yaml").write_text("packages: []\n")
            result = discover_pnpm_workspace(root)
            # Falls back to generic discovery
            self.assertGreaterEqual(len(result), 1)

    def test_invalid_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"name": "root"}')
            (root / "pnpm-workspace.yaml").write_text("{{invalid yaml}}")
            result = discover_pnpm_workspace(root)
            # Falls back to generic discovery
            self.assertGreaterEqual(len(result), 1)

    def test_non_dict_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"name": "root"}')
            (root / "pnpm-workspace.yaml").write_text("- just_a_list")
            result = discover_pnpm_workspace(root)
            # Falls back to generic discovery
            self.assertGreaterEqual(len(result), 1)


class TestWorkspaceResult(unittest.TestCase):
    """Test WorkspaceResult data class."""

    def test_defaults(self):
        result = WorkspaceResult()
        self.assertEqual(result.total_findings, 0)
        self.assertEqual(result.total_projects, 0)
        self.assertEqual(result.scanned_projects, 0)
        self.assertEqual(result.failed_projects, 0)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.duration_ms, 0)

    def test_to_dict(self):
        result = WorkspaceResult()
        d = result.to_dict()
        self.assertIn("total_projects", d)
        self.assertIn("scanned_projects", d)
        self.assertIn("failed_projects", d)
        self.assertIn("total_findings", d)
        self.assertIn("duration_ms", d)
        self.assertIn("errors", d)


class TestSkipDirs(unittest.TestCase):
    """Test SKIP_DIRS constant."""

    def test_contains_expected_dirs(self):
        self.assertIn("node_modules", SKIP_DIRS)
        self.assertIn(".git", SKIP_DIRS)
        self.assertIn("__pycache__", SKIP_DIRS)
        self.assertIn("dist", SKIP_DIRS)
        self.assertIn("build", SKIP_DIRS)


class TestNpmManifestGlobs(unittest.TestCase):
    """Test NPM_MANIFEST_GLOBS constant."""

    def test_contains_package_json(self):
        self.assertIn("**/package.json", NPM_MANIFEST_GLOBS)

    def test_contains_lockfiles(self):
        self.assertIn("**/pnpm-lock.yaml", NPM_MANIFEST_GLOBS)
        self.assertIn("**/package-lock.json", NPM_MANIFEST_GLOBS)
        self.assertIn("**/yarn.lock", NPM_MANIFEST_GLOBS)


if __name__ == "__main__":
    unittest.main()