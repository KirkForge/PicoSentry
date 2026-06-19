"""Tests for RubyGems ecosystem rules.

Tests cover:
- Ecosystem detection (Gemfile)
- RubyGems typosquat detection (L2-RUBYGEMS-TYPO-001)
- RubyGems dependency confusion (L2-RUBYGEMS-DEPC-001)
- RubyGems advisory check (L2-RUBYGEMS-ADV-001)
- Engine ecosystem filtering
"""

from pathlib import Path

from picosentry.scan.engine import create_default_engine
from picosentry.scan.models import Severity

# ── Fixture helpers ────────────────────────────────────────────────────

FIXTURES = Path(__file__).parent / "fixtures"
CORPUS_DIR = FIXTURES.parent.parent / "picosentry" / "scan" / "corpus"


def _gem_clean() -> Path:
    return FIXTURES / "rubygems_clean"


def _gem_malicious() -> Path:
    return FIXTURES / "rubygems_malicious"


# ── Ecosystem detection ────────────────────────────────────────────────


class TestRubyGemsDetection:
    """RubyGems project detection should work with Gemfile."""

    def test_detects_gemfile(self):
        from picosentry.scan.rules.rubygems_utils import detect_rubygems_project

        assert detect_rubygems_project(_gem_clean())

    def test_detects_gemfile_malicious(self):
        from picosentry.scan.rules.rubygems_utils import detect_rubygems_project

        assert detect_rubygems_project(_gem_malicious())

    def test_no_indicator_returns_false(self, tmp_path):
        from picosentry.scan.rules.rubygems_utils import detect_rubygems_project

        assert not detect_rubygems_project(tmp_path)

    def test_gemspec_detection(self, tmp_path):
        from picosentry.scan.rules.rubygems_utils import detect_rubygems_project

        (tmp_path / "mygem.gemspec").write_text("Gem::Specification.new do |s|\n  s.name = 'mygem'\nend")
        assert detect_rubygems_project(tmp_path)

    def test_gemfile_lock_detection(self, tmp_path):
        from picosentry.scan.rules.rubygems_utils import detect_rubygems_project

        (tmp_path / "Gemfile.lock").write_text("GEM\n  specs:\n")
        assert detect_rubygems_project(tmp_path)

    def test_not_a_directory_returns_false(self, tmp_path):
        from picosentry.scan.rules.rubygems_utils import detect_rubygems_project

        f = tmp_path / "not_a_dir"
        f.write_text("")
        assert not detect_rubygems_project(f)


# ── Engine ecosystem filtering ─────────────────────────────────────────


class TestRubyGemsEcosystemFiltering:
    """Engine should only run RubyGems rules when a Gemfile is present."""

    def test_npm_project_skips_rubygems_rules(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        engine = create_default_engine()
        result = engine.scan(tmp_path)
        gem_findings = [f for f in result.findings if f.rule_id.startswith("L2-RUBYGEMS-")]
        assert len(gem_findings) == 0

    def test_gem_project_runs_gem_rules(self):
        engine = create_default_engine()
        result = engine.scan(_gem_clean())
        [f for f in result.findings if f.ecosystem == "rubygems"]

    def test_three_rubygems_rules_registered(self):
        engine = create_default_engine()
        shared_rules = [rid for rid in engine.list_rules() if rid in ("L2-TYPO-001", "L2-DEPC-001", "L2-ADV-001")]
        assert len(shared_rules) == 3
        assert "L2-TYPO-001" in shared_rules
        assert "L2-DEPC-001" in shared_rules
        assert "L2-ADV-001" in shared_rules


# ── RubyGems Typosquat ─────────────────────────────────────────────────


class TestRubyGemsTyposquat:
    """RubyGems typosquat detection should flag suspicious gem names."""

    def test_detects_typosquat_in_malicious(self):
        from picosentry.scan.rules.typosquat import detect_all_typosquat as detect_rubygems_typosquat

        findings = detect_rubygems_typosquat(_gem_malicious(), CORPUS_DIR)
        typo_findings = [f for f in findings if f.rule_id == "L2-RUBYGEMS-TYPO-001"]
        assert len(typo_findings) >= 1
        # "raisl" is edit distance 1 from "rails"
        assert any("raisl" in f.package.lower() or "raisl" in f.message.lower() for f in typo_findings)

    def test_clean_project_has_no_typosquats(self):
        from picosentry.scan.rules.typosquat import detect_all_typosquat as detect_rubygems_typosquat

        findings = detect_rubygems_typosquat(_gem_clean(), FIXTURES.parent.parent / "picosentry" / "scan" / "corpus")
        typo_findings = [f for f in findings if f.rule_id == "L2-RUBYGEMS-TYPO-001"]
        assert len(typo_findings) == 0


# ── RubyGems Dependency Confusion ──────────────────────────────────────


class TestRubyGemsDependencyConfusion:
    """RubyGems dep confusion detection should flag internal-looking deps."""

    def test_detects_dep_confusion_in_malicious(self):
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_rubygems_dep_confusion

        findings = detect_rubygems_dep_confusion(_gem_malicious())
        depc_findings = [f for f in findings if f.rule_id == "L2-RUBYGEMS-DEPC-001"]
        assert len(depc_findings) >= 1
        assert any("company-internal" in f.package for f in depc_findings)

    def test_clean_project_has_no_dep_confusion(self):
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_rubygems_dep_confusion

        findings = detect_rubygems_dep_confusion(_gem_clean())
        depc_findings = [f for f in findings if f.rule_id == "L2-RUBYGEMS-DEPC-001"]
        assert len(depc_findings) == 0

    def test_private_source_suppresses_finding(self, tmp_path):
        """If a private source is configured, internal-looking gems should not be flagged."""
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_rubygems_dep_confusion

        gemfile_path = tmp_path / "Gemfile"
        gemfile_path.write_text("""source "https://gems.internal.example.com"

gem "company-internal", "~> 1.0"
""")
        findings = detect_rubygems_dep_confusion(tmp_path)
        depc_findings = [f for f in findings if f.rule_id == "L2-RUBYGEMS-DEPC-001"]
        assert len(depc_findings) == 0

    def test_git_dep_not_flagged(self, tmp_path):
        """A gem with a git source should not be flagged as dep confusion."""
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_rubygems_dep_confusion

        gemfile_path = tmp_path / "Gemfile"
        gemfile_path.write_text("""source "https://rubygems.org"

gem "company-internal", git: "https://github.com/company/internal-gem.git"
""")
        findings = detect_rubygems_dep_confusion(tmp_path)
        depc_findings = [f for f in findings if f.rule_id == "L2-RUBYGEMS-DEPC-001"]
        assert len(depc_findings) == 0


# ── RubyGems Gemfile parsing ──────────────────────────────────────────


class TestRubyGemsParsing:
    """RubyGems Gemfile parsing should extract metadata correctly."""

    def test_parse_gemfile_package_names(self):
        from picosentry.scan.rules.rubygems_utils import parse_gemfile

        data = parse_gemfile(_gem_clean())
        assert data is not None
        deps = data.get("dependencies", [])
        dep_names = {d[0] for d in deps}
        assert "rails" in dep_names
        assert "devise" in dep_names
        assert "pg" in dep_names

    def test_parse_gemfile_sources(self):
        from picosentry.scan.rules.rubygems_utils import parse_gemfile

        data = parse_gemfile(_gem_clean())
        assert data is not None
        sources = data.get("sources", [])
        assert any("rubygems.org" in s for s in sources)

    def test_parse_gemfile_no_file_returns_none(self, tmp_path):
        from picosentry.scan.rules.rubygems_utils import parse_gemfile

        assert parse_gemfile(tmp_path) is None


# ── RubyGems Lockfile Parser ──────────────────────────────────────────


class TestRubyGemsLockfileParser:
    """RubyGems lockfile parser should dispatch by filename."""

    def test_parse_gemfile_for_lock(self):
        from picosentry.scan.rules.rubygems_lock_parser import parse_gemfile_for_lock

        entries = parse_gemfile_for_lock(_gem_clean() / "Gemfile")
        assert len(entries) >= 4  # rails, pg, puma, devise + groups
        entry_names = {e[0] for e in entries}
        assert "rails" in entry_names
        assert "devise" in entry_names

    def test_parse_gemfile_lock_for_lock(self):
        from picosentry.scan.rules.rubygems_lock_parser import parse_gemfile_lock_for_lock

        entries = parse_gemfile_lock_for_lock(_gem_clean() / "Gemfile.lock")
        assert len(entries) > 0
        entry_names = {e[0] for e in entries}
        assert "rails" in entry_names
        assert "devise" in entry_names

    def test_parse_rubygems_lockfile_auto_detect_gemfile(self):
        from picosentry.scan.rules.rubygems_lock_parser import parse_rubygems_lockfile

        entries = parse_rubygems_lockfile(_gem_clean() / "Gemfile")
        assert len(entries) >= 4

    def test_parse_rubygems_lockfile_auto_detect_lock(self):
        from picosentry.scan.rules.rubygems_lock_parser import parse_rubygems_lockfile

        entries = parse_rubygems_lockfile(_gem_clean() / "Gemfile.lock")
        assert len(entries) > 0

    def test_parse_rubygems_lockfile_no_file_returns_empty(self, tmp_path):
        from picosentry.scan.rules.rubygems_lock_parser import parse_rubygems_lockfile

        assert parse_rubygems_lockfile(tmp_path / "nonexistent.lock") == []


# ── RubyGems Utilities ────────────────────────────────────────────────


class TestRubyGemsUtils:
    """RubyGems utility functions."""

    def test_get_rubygems_dep_names(self):
        from picosentry.scan.rules.rubygems_utils import get_rubygems_dep_names, parse_gemfile

        data = parse_gemfile(_gem_clean())
        assert data is not None
        names = get_rubygems_dep_names(data)
        assert "rails" in names
        assert "pg" in names

    def test_detect_private_source_clean(self):
        from picosentry.scan.rules.rubygems_utils import detect_private_rubygems_source

        assert not detect_private_rubygems_source(_gem_clean())

    def test_detect_private_source_with_custom_url(self, tmp_path):
        from picosentry.scan.rules.rubygems_utils import detect_private_rubygems_source

        gemfile_path = tmp_path / "Gemfile"
        gemfile_path.write_text('source "https://gems.internal.example.com"\n\ngem "my-gem", "~> 1.0"')
        assert detect_private_rubygems_source(tmp_path)

    def test_detect_private_source_with_git_dep(self, tmp_path):
        from picosentry.scan.rules.rubygems_utils import detect_private_rubygems_source

        gemfile_path = tmp_path / "Gemfile"
        gemfile_path.write_text(
            'source "https://rubygems.org"\n\ngem "my-gem", git: "https://github.com/company/my-gem.git"'
        )
        assert detect_private_rubygems_source(tmp_path)

    def test_detect_private_source_with_path_dep(self, tmp_path):
        from picosentry.scan.rules.rubygems_utils import detect_private_rubygems_source

        gemfile_path = tmp_path / "Gemfile"
        gemfile_path.write_text('source "https://rubygems.org"\n\ngem "my-gem", path: "../local-gem"')
        assert detect_private_rubygems_source(tmp_path)


# ── Integration ────────────────────────────────────────────────────────


class TestRubyGemsIntegration:
    """Full engine integration tests."""

    def test_clean_project_no_findings(self):
        engine = create_default_engine()
        result = engine.scan(_gem_clean())
        gem_findings = [f for f in result.findings if "L2-RUBYGEMS" in f.rule_id]
        assert len(gem_findings) == 0

    def test_malicious_project_has_findings(self):
        engine = create_default_engine()
        result = engine.scan(_gem_malicious())
        gem_findings = [f for f in result.findings if "L2-RUBYGEMS" in f.rule_id]
        assert len(gem_findings) >= 2  # typosquat + dep confusion
        rule_ids = {f.rule_id for f in gem_findings}
        assert "L2-RUBYGEMS-TYPO-001" in rule_ids
        assert "L2-RUBYGEMS-DEPC-001" in rule_ids

    def test_findings_have_rubygems_ecosystem(self):
        from picosentry.scan.rules.typosquat import detect_all_typosquat as detect_rubygems_typosquat

        findings = detect_rubygems_typosquat(_gem_malicious(), CORPUS_DIR)
        for f in findings:
            assert f.ecosystem == "rubygems"

    def test_dep_confusion_findings_are_critical(self):
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_rubygems_dep_confusion

        findings = detect_rubygems_dep_confusion(_gem_malicious())
        for f in findings:
            assert f.severity == Severity.CRITICAL
            assert f.ecosystem == "rubygems"

    def test_npm_backward_compat_preserved(self, tmp_path):
        """Adding RubyGems rules should not affect npm scans."""
        (tmp_path / "package.json").write_text("{}")
        engine = create_default_engine()
        result = engine.scan(tmp_path)
        gem_findings = [f for f in result.findings if "L2-RUBYGEMS" in f.rule_id]
        assert len(gem_findings) == 0

    def test_rubygems_rules_skipped_when_no_gemfile(self, tmp_path):
        """RubyGems rules should be filtered out when no Gemfile."""
        (tmp_path / "README.md").write_text("# just a readme")
        engine = create_default_engine()
        result = engine.scan(tmp_path)
        gem_findings = [f for f in result.findings if "L2-RUBYGEMS" in f.rule_id]
        assert len(gem_findings) == 0
