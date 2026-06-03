"""
Tests for L2-SIDELOAD-001: Protocol sideloading detection.

Deterministic: same input + same corpus = same findings. No HTTP. No randomness.
"""

import json
from pathlib import Path

import pytest

from picosentry.scan.models import Confidence, Severity
from picosentry.scan.rules.sideloading import detect_sideloading


@pytest.fixture
def corpus_dir(tmp_path):
    """Minimal corpus directory (sideloading doesn't use corpus)."""
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "npm_top_packages.json").write_text("[]")
    return corpus


def _write_pkg(target: Path, data: dict) -> Path:
    """Write a package.json and return its path."""
    pkg_path = target / "package.json"
    pkg_path.write_text(json.dumps(data, indent=2))
    return pkg_path


# --- Root package.json tests ---


class TestGitSshProtocol:
    """git+ssh:// dependencies — CRITICAL (bypasses integrity + unencrypted)."""

    def test_git_ssh_dependency(self, tmp_path, corpus_dir):
        """git+ssh:// in dependencies → CRITICAL."""
        _write_pkg(
            tmp_path,
            {
                "name": "test-pkg",
                "version": "1.0.0",
                "dependencies": {"malicious-lib": "git+ssh://git@github.com:evil/repo.git"},
            },
        )
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "L2-SIDELOAD-001"
        assert f.package == "malicious-lib"
        assert f.severity == Severity.CRITICAL
        assert "git+ssh://" in f.evidence

    def test_git_ssh_dev_dependency(self, tmp_path, corpus_dir):
        """git+ssh:// in devDependencies → CRITICAL."""
        _write_pkg(
            tmp_path,
            {
                "name": "test-pkg",
                "version": "1.0.0",
                "devDependencies": {"dev-lib": "git+ssh://git@github.com:evil/dev.git"},
            },
        )
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL


class TestGitProtocol:
    """git:// dependencies — CRITICAL (bypasses integrity, unencrypted)."""

    def test_git_protocol_dependency(self, tmp_path, corpus_dir):
        """git:// in dependencies → CRITICAL."""
        _write_pkg(tmp_path, {"name": "test-pkg", "dependencies": {"unverified-pkg": "git://github.com/evil/repo.git"}})
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "git://" in findings[0].evidence


class TestGitHttpsProtocol:
    """git+https:// dependencies — HIGH (bypasses integrity)."""

    def test_git_https_dependency(self, tmp_path, corpus_dir):
        """git+https:// in dependencies → HIGH."""
        _write_pkg(
            tmp_path, {"name": "test-pkg", "dependencies": {"forked-lib": "git+https://github.com/forked/lib.git"}}
        )
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_git_http_protocol(self, tmp_path, corpus_dir):
        """git+http:// → CRITICAL (unencrypted)."""
        _write_pkg(
            tmp_path, {"name": "test-pkg", "dependencies": {"insecure-pkg": "git+http://github.com/evil/repo.git"}}
        )
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL


class TestGithubShorthand:
    """github: shorthand dependencies — HIGH."""

    def test_github_shorthand(self, tmp_path, corpus_dir):
        """github: shorthand → HIGH."""
        _write_pkg(tmp_path, {"name": "test-pkg", "dependencies": {"some-lib": "github:user/repo"}})
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "github:" in findings[0].evidence


class TestFileProtocol:
    """file:// dependencies — MEDIUM (not reproducible)."""

    def test_file_protocol(self, tmp_path, corpus_dir):
        """file:// in dependencies → MEDIUM."""
        _write_pkg(tmp_path, {"name": "test-pkg", "dependencies": {"local-lib": "file:../local-lib"}})
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "file:" in findings[0].evidence

    def test_file_protocol_dev(self, tmp_path, corpus_dir):
        """file:// in devDependencies → MEDIUM."""
        _write_pkg(tmp_path, {"name": "test-pkg", "devDependencies": {"local-dev": "file:../local-dev"}})
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 1


class TestLinkProtocol:
    """link: dependencies — MEDIUM (symlink, not portable)."""

    def test_link_protocol(self, tmp_path, corpus_dir):
        """link: in dependencies → MEDIUM."""
        _write_pkg(tmp_path, {"name": "test-pkg", "dependencies": {"linked-lib": "link:../linked-lib"}})
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "link:" in findings[0].evidence


class TestMixedProtocols:
    """Multiple protocols in the same package.json."""

    def test_mixed_protocols(self, tmp_path, corpus_dir):
        """Multiple non-registry protocols → multiple findings."""
        _write_pkg(
            tmp_path,
            {
                "name": "test-pkg",
                "dependencies": {
                    "git-dep": "git+https://github.com/org/repo.git",
                    "file-dep": "file:../local-pkg",
                    "github-dep": "github:user/repo",
                },
            },
        )
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 3
        severities = {f.severity for f in findings}
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities

    def test_multiple_git_deps(self, tmp_path, corpus_dir):
        """Multiple git deps → one finding per dependency."""
        _write_pkg(
            tmp_path,
            {
                "name": "test-pkg",
                "dependencies": {
                    "dep-a": "git+ssh://git@github.com:a/pkg.git",
                    "dep-b": "git+ssh://git@github.com:b/pkg.git",
                },
            },
        )
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 2
        packages = {f.package for f in findings}
        assert "dep-a" in packages
        assert "dep-b" in packages


class TestCleanPackages:
    """Packages with only registry versions → no findings."""

    def test_clean_registry_deps(self, tmp_path, corpus_dir):
        """Normal registry versions → no findings."""
        _write_pkg(
            tmp_path,
            {
                "name": "clean-pkg",
                "version": "1.0.0",
                "dependencies": {"lodash": "^4.17.21", "express": "~4.18.2", "react": "18.2.0"},
                "devDependencies": {"jest": "^29.0.0", "typescript": "^5.0.0"},
            },
        )
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 0

    def test_empty_package(self, tmp_path, corpus_dir):
        """Package with no dependencies → no findings."""
        _write_pkg(tmp_path, {"name": "empty-pkg", "version": "1.0.0"})
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 0

    def test_no_package_json(self, tmp_path, corpus_dir):
        """Missing package.json → no findings, no crash."""
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 0


class TestPeerAndOptionalDeps:
    """Non-registry protocols in peerDependencies and optionalDependencies."""

    def test_peer_dep_git(self, tmp_path, corpus_dir):
        """git+ssh:// in peerDependencies → CRITICAL."""
        _write_pkg(
            tmp_path,
            {
                "name": "test-pkg",
                "peerDependencies": {"react-native": "git+ssh://git@github.com:fork/react-native.git"},
            },
        )
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_optional_dep_file(self, tmp_path, corpus_dir):
        """file: in optionalDependencies → MEDIUM."""
        _write_pkg(tmp_path, {"name": "test-pkg", "optionalDependencies": {"native-addon": "file:./native"}})
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM


class TestNodeModulesScan:
    """Scan node_modules for transitive sideloading."""

    def test_node_modules_git_dep(self, tmp_path, corpus_dir):
        """Transitive dependency with git:// protocol → CRITICAL."""
        root_pkg = tmp_path / "package.json"
        root_pkg.write_text(json.dumps({"name": "root-pkg", "dependencies": {"transitive": "^1.0.0"}}))

        nm = tmp_path / "node_modules" / "transitive"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(
            json.dumps(
                {
                    "name": "transitive",
                    "version": "1.0.0",
                    "dependencies": {"evil-subdep": "git://github.com/evil/subdep.git"},
                }
            )
        )

        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 1
        assert findings[0].package == "evil-subdep"
        assert findings[0].severity == Severity.CRITICAL

    def test_scoped_package_git_dep(self, tmp_path, corpus_dir):
        """Scoped package in node_modules with github: shorthand → HIGH."""
        root_pkg = tmp_path / "package.json"
        root_pkg.write_text(json.dumps({"name": "root-pkg"}))

        scoped = tmp_path / "node_modules" / "@scope"
        scoped.mkdir(parents=True)
        pkg_dir = scoped / "scoped-pkg"
        pkg_dir.mkdir()
        (pkg_dir / "package.json").write_text(
            json.dumps(
                {
                    "name": "@scope/scoped-pkg",
                    "version": "1.0.0",
                    "dependencies": {"side-channels": "github:evil/side-channels"},
                }
            )
        )

        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


class TestDeterminism:
    """Same input = same output. No randomness."""

    def test_deterministic_findings(self, tmp_path, corpus_dir):
        """Two scans on same input produce identical findings."""
        _write_pkg(
            tmp_path,
            {
                "name": "determinism-test",
                "dependencies": {"git-dep": "git+https://github.com/org/pkg.git", "file-dep": "file:../local"},
            },
        )

        findings_a = detect_sideloading(tmp_path, corpus_dir)
        findings_b = detect_sideloading(tmp_path, corpus_dir)

        # Same count
        assert len(findings_a) == len(findings_b)
        # Same content
        for a, b in zip(findings_a, findings_b, strict=False):
            assert a.rule_id == b.rule_id
            assert a.package == b.package
            assert a.severity == b.severity
            assert a.evidence == b.evidence


class TestConfidence:
    """All sideloading findings have EXACT confidence (pattern match)."""

    def test_exact_confidence(self, tmp_path, corpus_dir):
        """Protocol prefix matches are always EXACT confidence."""
        _write_pkg(
            tmp_path, {"name": "test-pkg", "dependencies": {"git-dep": "git+ssh://git@github.com:evil/repo.git"}}
        )
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 1
        assert findings[0].confidence == Confidence.EXACT


class TestInvalidPackageJson:
    """Graceful handling of malformed package.json."""

    def test_malformed_json(self, tmp_path, corpus_dir):
        """Malformed package.json → no crash, no findings."""
        pkg = tmp_path / "package.json"
        pkg.write_text("{invalid json!!!")
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 0

    def test_non_dict_deps(self, tmp_path, corpus_dir):
        """dependencies as array instead of dict → no findings."""
        _write_pkg(tmp_path, {"name": "bad-pkg", "dependencies": ["lodash", "express"]})
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 0

    def test_non_string_version(self, tmp_path, corpus_dir):
        """Version as object instead of string → no findings."""
        _write_pkg(tmp_path, {"name": "bad-pkg", "dependencies": {"some-dep": {"version": "1.0.0"}}})
        findings = detect_sideloading(tmp_path, corpus_dir)
        assert len(findings) == 0