"""
Tests for pnpm_lock_parser — Parse pnpm-lock.yaml v6+ for lockfile analysis.
"""

from picosentry.scan.rules.pnpm_lock_parser import (
    _parse_pnpm_pkg_key,
    find_missing_integrity,
    find_weak_integrity,
    get_pnpm_importer_deps,
    get_pnpm_package,
    parse_pnpm_lockfile,
)

# Sample pnpm-lock.yaml v6 content
PNPM_LOCK_V6 = """lockfileVersion: '6.0'

importers:
  .:
    dependencies:
      lodash:
        version: 4.17.21
      express:
        version: 4.18.2
    devDependencies:
      typescript:
        version: 5.3.3

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1k3vkfBjiL5N3O4G2qHW1uiRK9jMLN8w2Oe4k9GRg9NdbJ7A==}
    engines: {node: '>=0.10.0'}

  /express@4.18.2:
    resolution: {integrity: sha512-5884z0T1R9M1e0R2xE0BwGFiZlSO6NdnR8VqDnD7LkF8MhOpGsoFP3sU4IN0p2R8L5N-2M0d9k8O5a4B4G2W1A==}
    engines: {node: '>= 0.10.0'}
    dependencies:
      accepts: 1.3.8
      body-parser: 1.20.1

  /typescript@5.3.3:
    resolution: {integrity: sha512-pXJ5RQ9R9R9R9R9R9R9R9R9R9R9R9R9R9R9R9==}
    engines: {node: '>=4.2.0'}
    dev: true
"""

PNPM_LOCK_V6_WEAK = """lockfileVersion: '6.0'

importers:
  .:
    dependencies:
      old-pkg:
        version: 1.0.0

packages:

  /old-pkg@1.0.0:
    resolution: {integrity: sha1-abc123def456}
    engines: {node: '>=0.10.0'}

  /no-integrity-pkg@2.0.0:
    engines: {node: '>=0.10.0'}
"""

PNPM_LOCK_V9 = """lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      react:
        version: 18.2.0
    devDependencies:
      vitest:
        version: 1.2.0

packages:

  /react@18.2.0:
    resolution: {integrity: sha512-g4T1T9fO58R2T9K2sO8qQF7F2RT3Oq6jK2gYF1VfR8p6+G3y3G2yB1N3z+eh1edOC3c3IeHkS3z1p4yK3a3a3A==}

  /vitest@1.2.0:
    resolution: {integrity: sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1k3vkfBjiL5N3O4G2qHW1uiRK9jMLN8w2Oe4k9GRg9NdbJ7A==}
    dev: true
"""


class TestPnpmLockParser:
    """Test pnpm-lock.yaml v6+ parser."""

    def test_parse_v6_importers(self):
        """Parse importers section from v6 lockfile."""
        lockfile = parse_pnpm_lockfile(PNPM_LOCK_V6)
        assert lockfile.lockfile_version == "6.0"
        assert "." in lockfile.importers
        deps = lockfile.importers["."]
        assert "lodash" in deps
        assert "express" in deps
        assert "typescript" in deps

    def test_parse_v6_packages(self):
        """Parse packages section from v6 lockfile."""
        lockfile = parse_pnpm_lockfile(PNPM_LOCK_V6)
        assert len(lockfile.packages) == 3

        # Find lodash
        lodash = get_pnpm_package(lockfile, "lodash")
        assert lodash is not None
        assert lodash.version == "4.17.21"
        assert "sha512" in lodash.integrity

    def test_parse_v6_express_deps(self):
        """Express package has sub-dependencies listed."""
        lockfile = parse_pnpm_lockfile(PNPM_LOCK_V6)
        express = get_pnpm_package(lockfile, "express")
        assert express is not None
        assert "accepts" in express.deps
        assert "body-parser" in express.deps

    def test_parse_v9_lockfile(self):
        """Parse v9 lockfile format."""
        lockfile = parse_pnpm_lockfile(PNPM_LOCK_V9)
        assert lockfile.lockfile_version == "9.0"
        react = get_pnpm_package(lockfile, "react")
        assert react is not None
        assert react.version == "18.2.0"

    def test_missing_integrity(self):
        """Find packages without integrity hashes."""
        lockfile = parse_pnpm_lockfile(PNPM_LOCK_V6_WEAK)
        missing = find_missing_integrity(lockfile)
        # no-integrity-pkg should be flagged
        missing_names = [name for name, _ in missing]
        assert "no-integrity-pkg" in missing_names

    def test_weak_integrity(self):
        """Find packages using weak integrity algorithms."""
        lockfile = parse_pnpm_lockfile(PNPM_LOCK_V6_WEAK)
        weak = find_weak_integrity(lockfile)
        # old-pkg uses sha1 — should be flagged
        weak_names = [name for name, _, _ in weak]
        assert "old-pkg" in weak_names

    def test_get_importer_deps(self):
        """Get dependencies for a specific importer."""
        lockfile = parse_pnpm_lockfile(PNPM_LOCK_V6)
        deps = get_pnpm_importer_deps(lockfile, ".")
        assert "lodash" in deps
        assert "express" in deps
        assert "typescript" in deps

    def test_get_importer_deps_nonexistent(self):
        """Non-existent importer returns empty dict."""
        lockfile = parse_pnpm_lockfile(PNPM_LOCK_V6)
        deps = get_pnpm_importer_deps(lockfile, "nonexistent")
        assert len(deps) == 0

    def test_get_package_by_name_and_version(self):
        """Look up package by name and version."""
        lockfile = parse_pnpm_lockfile(PNPM_LOCK_V6)
        lodash = get_pnpm_package(lockfile, "lodash", "4.17.21")
        assert lodash is not None
        assert lodash.version == "4.17.21"

    def test_get_package_not_found(self):
        """Look up non-existent package returns None."""
        lockfile = parse_pnpm_lockfile(PNPM_LOCK_V6)
        result = get_pnpm_package(lockfile, "nonexistent")
        assert result is None

    def test_empty_lockfile(self):
        """Empty content returns empty lockfile."""
        lockfile = parse_pnpm_lockfile("")
        assert lockfile.lockfile_version == ""
        assert len(lockfile.packages) == 0

    def test_invalid_yaml(self):
        """Invalid YAML returns empty lockfile."""
        lockfile = parse_pnpm_lockfile("{{{{invalid yaml")
        assert len(lockfile.packages) == 0


class TestPnpmPkgKeyParsing:
    """Test pnpm-lock.yaml package key parsing."""

    def test_regular_package(self):
        """Parse regular package key: /lodash@4.17.21"""
        name, version, is_aliased = _parse_pnpm_pkg_key("/lodash@4.17.21")
        assert name == "lodash"
        assert version == "4.17.21"
        assert is_aliased is False

    def test_scoped_package(self):
        """Parse scoped package key: /@types/node@20.0.0"""
        name, version, is_aliased = _parse_pnpm_pkg_key("/@types/node@20.0.0")
        assert name == "@types/node"
        assert version == "20.0.0"
        assert is_aliased is False

    def test_peer_dep_suffix(self):
        """Parse aliased key with peer deps: /react@18.2.0(react-dom@18.2.0)"""
        name, version, is_aliased = _parse_pnpm_pkg_key("/react@18.2.0(react-dom@18.2.0)")
        assert name == "react"
        assert version == "18.2.0"
        assert is_aliased is True

    def test_no_version(self):
        """Parse key with no version: /lodash"""
        name, version, is_aliased = _parse_pnpm_pkg_key("/lodash")
        assert name == "lodash"
        assert version == ""
        assert is_aliased is False


class TestPnpmLockDriftIntegration:
    """Integration tests: pnpm-lock.yaml drift detection via L2-LOCK-001."""

    def test_pnpm_missing_dep_detected(self, tmp_path):
        """Dependency in package.json but not in pnpm-lock.yaml should be flagged."""
        from picosentry.scan.engine import create_default_engine

        project = tmp_path / "test_project"
        project.mkdir()
        (project / "package.json").write_text(
            '{"name":"test-pnpm","version":"1.0.0","dependencies":{"lodash":"^4.17.21","missing-dep":"^1.0.0"}}',
            encoding="utf-8",
        )
        (project / "pnpm-lock.yaml").write_text(
            """lockfileVersion: '6.0'

importers:
  .:
    dependencies:
      lodash:
        version: 4.17.21

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1k3vkfBjiL5N3O4G2qHW1uiRK9jMLN8w2Oe4k9GRg9NdbJ7A==}
""",
            encoding="utf-8",
        )

        engine = create_default_engine()
        result = engine.scan(project)

        lock_findings = [f for f in result.findings if f.rule_id == "L2-LOCK-001"]
        # Should detect missing-dep in lockfile
        assert any("missing" in f.message.lower() or "missing" in (f.evidence or "").lower() for f in lock_findings), (
            f"Expected missing dep finding, got: {[f.message for f in lock_findings]}"
        )

    def test_pnpm_no_lockfile_flagged(self, tmp_path):
        """Project with dependencies but no lockfile should be flagged."""
        from picosentry.scan.engine import create_default_engine

        project = tmp_path / "test_project"
        project.mkdir()
        (project / "package.json").write_text(
            '{"name":"test-no-lock","version":"1.0.0","dependencies":{"lodash":"^4.17.21"}}',
            encoding="utf-8",
        )

        engine = create_default_engine()
        result = engine.scan(project)

        lock_findings = [f for f in result.findings if f.rule_id == "L2-LOCK-001"]
        assert len(lock_findings) > 0, "Should flag missing lockfile"
        assert any("no lockfile" in f.message.lower() for f in lock_findings)

    def test_pnpm_dangerously_allow_builds_in_workspace_yaml(self, tmp_path):
        """pnpm-workspace.yaml with dangerouslyAllowAllBuilds should be flagged."""
        from picosentry.scan.engine import create_default_engine

        project = tmp_path / "test_project"
        project.mkdir()
        (project / "package.json").write_text(
            '{"name":"test-ws","version":"1.0.0","dependencies":{}}',
            encoding="utf-8",
        )
        (project / "pnpm-workspace.yaml").write_text(
            "packages:\n  - 'apps/*'\n  - 'packages/*'\ndangerouslyAllowAllBuilds: true\n",
            encoding="utf-8",
        )
        (project / "pnpm-lock.yaml").write_text(
            "lockfileVersion: '6.0'\n",
            encoding="utf-8",
        )

        engine = create_default_engine()
        result = engine.scan(project)

        lock_findings = [f for f in result.findings if f.rule_id == "L2-LOCK-001"]
        assert any("dangerouslyAllowAllBuilds" in f.message for f in lock_findings), (
            f"Expected dangerouslyAllowAllBuilds finding, got: {[f.message for f in lock_findings]}"
        )
