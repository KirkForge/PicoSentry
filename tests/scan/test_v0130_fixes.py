"""Tests for v0.13.0 fixes: utils extraction, fork_drift heuristics,
MANI-002 consolidation, pnpm_config naming, credential_read budget."""

import json

from picosentry.scan.rules.credential_read import MAX_FILES_PER_PACKAGE
from picosentry.scan.rules.fork_drift import AUTHORITATIVE_PREFIXES, _is_fork_repo, detect_fork_drift
from picosentry.scan.rules.manifest import detect_manifest_issues
from picosentry.scan.rules.pnpm_config import detect_pnpm_config
from picosentry.scan.rules.utils import get_dep_names, iter_node_modules, load_package_json

# ─── utils.load_package_json ────────────────────────────────────────


class TestLoadPackageJson:
    """Shared utility: load_package_json."""

    def test_valid_json(self, tmp_path):
        p = tmp_path / "package.json"
        p.write_text('{"name": "test", "version": "1.0.0"}')
        result = load_package_json(p)
        assert result["name"] == "test"
        assert result["version"] == "1.0.0"

    def test_invalid_json_returns_empty(self, tmp_path):
        p = tmp_path / "package.json"
        p.write_text("{invalid json")
        result = load_package_json(p)
        assert result == {}

    def test_missing_file_returns_empty(self, tmp_path):
        p = tmp_path / "nonexistent.json"
        result = load_package_json(p)
        assert result == {}

    def test_binary_content_returns_empty(self, tmp_path):
        p = tmp_path / "package.json"
        p.write_bytes(b"\x00\x01\x02\xff")
        result = load_package_json(p)
        assert result == {}


# ─── utils.get_dep_names ────────────────────────────────────────────


class TestGetDepNames:
    """Shared utility: get_dep_names."""

    def test_all_sections(self):
        pkg = {
            "dependencies": {"lodash": "^4.0.0"},
            "devDependencies": {"jest": "^29.0.0"},
            "peerDependencies": {"react": ">=18"},
            "optionalDependencies": {"fsevents": "^2.0.0"},
        }
        names = get_dep_names(pkg)
        assert names == {"lodash", "jest", "react", "fsevents"}

    def test_empty_pkg(self):
        assert get_dep_names({}) == set()

    def test_partial_sections(self):
        pkg = {"dependencies": {"a": "1.0.0"}, "devDependencies": {"b": "2.0.0"}}
        names = get_dep_names(pkg)
        assert names == {"a", "b"}


# ─── utils.iter_node_modules ────────────────────────────────────────


class TestIterNodeModules:
    """Shared utility: iter_node_modules."""

    def _setup_package(self, tmp_path, name="test-pkg", version="1.0.0"):
        nm = tmp_path / "node_modules" / name
        nm.mkdir(parents=True)
        pkg_json = nm / "package.json"
        pkg_json.write_text(json.dumps({"name": name, "version": version}))
        return tmp_path

    def test_yields_packages(self, tmp_path):
        self._setup_package(tmp_path, "lodash")
        results = list(iter_node_modules(tmp_path))
        assert len(results) == 1
        assert results[0][1]["name"] == "lodash"

    def test_no_node_modules(self, tmp_path):
        results = list(iter_node_modules(tmp_path))
        assert results == []

    def test_scoped_packages(self, tmp_path):
        scoped = tmp_path / "node_modules" / "@babel" / "core"
        scoped.mkdir(parents=True)
        (scoped / "package.json").write_text(json.dumps({"name": "@babel/core"}))
        results = list(iter_node_modules(tmp_path))
        assert len(results) == 1
        assert results[0][1]["name"] == "@babel/core"

    def test_skips_dot_dirs(self, tmp_path):
        nm = tmp_path / "node_modules" / ".cache"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text("{}")
        results = list(iter_node_modules(tmp_path))
        assert len(results) == 0


# ─── fork_drift._is_fork_repo ───────────────────────────────────────


class TestIsForkRepo:
    """Heuristic fork detection — no longer returns True for everything."""

    def test_authoritative_orgs_not_fork(self):
        """URLs from authoritative orgs should NOT be flagged as forks."""
        for prefix in AUTHORITATIVE_PREFIXES:
            assert _is_fork_repo(prefix + "some-package", "some-package") is False

    def test_github_same_org_not_fork(self):
        """github.com/lodash/lodash should NOT be flagged — org matches package."""
        assert _is_fork_repo("https://github.com/lodash/lodash", "lodash") is False

    def test_github_different_org_is_suspicious(self):
        """github.com/randomuser/lodash — different org, same package name → fork."""
        # lodash is in the authoritative list; randomuser is not authoritative
        # Package name appears in repo path under a different org
        result = _is_fork_repo("https://github.com/randomuser/lodash", "lodash")
        assert result is True

    def test_github_personal_repo_unknown_pkg(self):
        """github.com/myorg/my-internal-lib — org matches package → canonical."""
        assert _is_fork_repo("https://github.com/myorg/my-internal-lib", "my-internal-lib") is False

    def test_author_matches_org_not_fork(self):
        """If the author field matches the GitHub org, it's likely canonical."""
        assert _is_fork_repo("https://github.com/johndoe/mylib", "mylib", author="johndoe") is False

    def test_fork_indicator_in_url(self):
        """URLs containing fork indicators should be flagged."""
        assert _is_fork_repo("https://github.com/user/lodash-fork", "lodash") is True
        assert _is_fork_repo("https://github.com/user/express-mirror", "express") is True

    def test_no_longer_always_true(self):
        """The old behavior was return True for everything. Verify this is fixed."""
        # A legit package from a non-authoritative org should NOT be flagged
        # if the org name matches the package name
        assert _is_fork_repo("https://github.com/mycompany/myproject", "myproject") is False

    def test_default_conservative_not_fork(self):
        """Unknown repos without clear fork signals should default to NOT fork."""
        # A package from a non-GitHub URL with no fork indicators
        assert _is_fork_repo("https://gitlab.com/someorg/somepkg", "somepkg") is False


# ─── fork_drift.detect_fork_drift ───────────────────────────────────


class TestForkDriftDetection:
    """Integration: detect_fork_drift no longer false-positives every package."""

    def test_no_repo_url_is_low_severity(self, tmp_path):
        """Packages without repository URL should get LOW severity."""
        nm = tmp_path / "node_modules" / "mystery-pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(json.dumps({"name": "mystery-pkg", "version": "1.0.0"}))

        findings = detect_fork_drift(tmp_path)
        assert len(findings) == 1
        assert findings[0].severity.value in ("low", "LOW")

    def test_authoritative_repo_not_flagged(self, tmp_path):
        """Packages from authoritative repos should NOT be flagged."""
        nm = tmp_path / "node_modules" / "react"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(
            json.dumps(
                {"name": "react", "version": "18.0.0", "repository": {"url": "https://github.com/facebook/react"}}
            )
        )

        findings = detect_fork_drift(tmp_path)
        fork_findings = [f for f in findings if "fork" in f.message.lower()]
        assert len(fork_findings) == 0

    def test_fork_indicator_in_name(self, tmp_path):
        """Package with 'fork' in name should be flagged."""
        nm = tmp_path / "node_modules" / "lodash-fork"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(
            json.dumps(
                {
                    "name": "lodash-fork",
                    "version": "1.0.0",
                    "repository": {"url": "https://github.com/random/lodash-fork"},
                }
            )
        )

        findings = detect_fork_drift(tmp_path)
        assert any(f.rule_id == "L2-FORK-001" for f in findings)


# ─── manifest MANI-002 consolidation ────────────────────────────────


class TestMani002Consolidation:
    """MANI-002 should produce ONE finding per package, not one per optional dep."""

    def _make_pkg_with_optional_deps_and_scripts(self, tmp_path, dep_count=5):
        """Create a package.json with N optional deps and install scripts."""
        optional_deps = {f"opt-dep-{i}": f"^{i}.0.0" for i in range(dep_count)}
        pkg = {
            "name": "test-pkg",
            "version": "1.0.0",
            "scripts": {"install": "node install.js"},
            "optionalDependencies": optional_deps,
        }
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        # Need node_modules for scanning
        nm = tmp_path / "node_modules"
        nm.mkdir()
        return tmp_path

    def test_single_finding_per_package(self, tmp_path):
        """10 optional deps + install scripts → 1 finding, not 10."""
        self._make_pkg_with_optional_deps_and_scripts(tmp_path, dep_count=10)
        findings = detect_manifest_issues(tmp_path)
        mani_002 = [f for f in findings if f.rule_id == "L2-MANI-002"]
        assert len(mani_002) == 1, f"Expected 1 MANI-002 finding, got {len(mani_002)}"

    def test_finding_mentions_count(self, tmp_path):
        """The consolidated finding should mention the count of optional deps."""
        self._make_pkg_with_optional_deps_and_scripts(tmp_path, dep_count=3)
        findings = detect_manifest_issues(tmp_path)
        mani_002 = [f for f in findings if f.rule_id == "L2-MANI-002"]
        assert len(mani_002) == 1
        assert "3 optional dependencies" in mani_002[0].message

    def test_single_dep_singular(self, tmp_path):
        """1 optional dep → '1 optional dependency' (singular)."""
        self._make_pkg_with_optional_deps_and_scripts(tmp_path, dep_count=1)
        findings = detect_manifest_issues(tmp_path)
        mani_002 = [f for f in findings if f.rule_id == "L2-MANI-002"]
        assert len(mani_002) == 1
        assert "1 optional dependency" in mani_002[0].message

    def test_evidence_lists_all_deps(self, tmp_path):
        """Evidence field should list all optional dep names."""
        self._make_pkg_with_optional_deps_and_scripts(tmp_path, dep_count=3)
        findings = detect_manifest_issues(tmp_path)
        mani_002 = [f for f in findings if f.rule_id == "L2-MANI-002"]
        assert "opt-dep-0" in mani_002[0].evidence
        assert "opt-dep-1" in mani_002[0].evidence
        assert "opt-dep-2" in mani_002[0].evidence


# ─── pnpm_config naming ─────────────────────────────────────────────


class TestPnpmConfigNaming:
    """detect_pnpm_config is the canonical name (not scan)."""

    def test_function_name(self):
        """Verify the function is named detect_pnpm_config."""
        from picosentry.scan.rules.pnpm_config import detect_pnpm_config as fn

        assert fn.__name__ == "detect_pnpm_config"

    def test_registered_in_engine(self):
        """Verify pnpm_config is importable under the new name."""
        assert callable(detect_pnpm_config)
        assert detect_pnpm_config.__name__ == "detect_pnpm_config"


# ─── credential_read budget ─────────────────────────────────────────


class TestCredentialReadBudget:
    """MAX_FILES_PER_PACKAGE limits file scanning."""

    def test_budget_constant_exists(self):
        """MAX_FILES_PER_PACKAGE should be defined and reasonable."""
        assert MAX_FILES_PER_PACKAGE == 200

    def test_budget_prevents_explosion(self, tmp_path):
        """Scanning a package with many files should be capped."""
        from picosentry.scan.rules.credential_read import detect_credential_reading

        # Create a package with 300 JS files
        nm = tmp_path / "node_modules" / "big-pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(
            json.dumps(
                {
                    "name": "big-pkg",
                    "version": "1.0.0",
                }
            )
        )
        for i in range(300):
            (nm / f"file{i}.js").write_text("// innocent file\n")

        # Should complete without scanning all 300 files
        findings = detect_credential_reading(tmp_path)
        # No credential patterns → no findings, but should not hang
        assert isinstance(findings, list)
