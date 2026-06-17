"""Tests for NuGet ecosystem rules.

Tests cover:
- Ecosystem detection (*.csproj, packages.config)
- NuGet typosquat detection (L2-NUGET-TYPO-001)
- NuGet dependency confusion (L2-NUGET-DEPC-001)
- NuGet advisory check (L2-NUGET-ADV-001)
- Engine ecosystem filtering
"""

from pathlib import Path

from picosentry.scan.engine import create_default_engine
from picosentry.scan.models import Severity

# ── Fixture helpers ────────────────────────────────────────────────────

FIXTURES = Path(__file__).parent / "fixtures"


def _nuget_clean() -> Path:
    return FIXTURES / "nuget_clean"


def _nuget_malicious() -> Path:
    return FIXTURES / "nuget_malicious"


# ── Ecosystem detection ────────────────────────────────────────────────


class TestNuGetDetection:
    """NuGet project detection should work with .csproj files."""

    def test_detects_csproj(self):
        from picosentry.scan.rules.nuget_utils import detect_nuget_project
        assert detect_nuget_project(_nuget_clean())

    def test_detects_csproj_malicious(self):
        from picosentry.scan.rules.nuget_utils import detect_nuget_project
        assert detect_nuget_project(_nuget_malicious())

    def test_no_indicator_returns_false(self, tmp_path):
        from picosentry.scan.rules.nuget_utils import detect_nuget_project
        assert not detect_nuget_project(tmp_path)

    def test_packages_config_detection(self, tmp_path):
        from picosentry.scan.rules.nuget_utils import detect_nuget_project
        (tmp_path / "packages.config").write_text("<packages></packages>")
        assert detect_nuget_project(tmp_path)

    def test_nuget_config_detection(self, tmp_path):
        from picosentry.scan.rules.nuget_utils import detect_nuget_project
        (tmp_path / "nuget.config").write_text("<configuration></configuration>")
        assert detect_nuget_project(tmp_path)

    def test_not_a_directory_returns_false(self, tmp_path):
        from picosentry.scan.rules.nuget_utils import detect_nuget_project
        f = tmp_path / "not_a_dir"
        f.write_text("")
        assert not detect_nuget_project(f)


# ── Engine ecosystem filtering ─────────────────────────────────────────


class TestNuGetEcosystemFiltering:
    """Engine should only run NuGet rules when .csproj is present."""

    def test_npm_project_skips_nuget_rules(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        engine = create_default_engine()
        result = engine.scan(tmp_path)
        nuget_findings = [f for f in result.findings if f.ecosystem == "nuget"]
        assert len(nuget_findings) == 0

    def test_nuget_project_runs_nuget_rules(self):
        engine = create_default_engine()
        result = engine.scan(_nuget_clean())
        [f for f in result.findings if f.ecosystem == "nuget"]

    def test_three_nuget_rules_registered(self):
        engine = create_default_engine()
        shared_rules = [rid for rid in engine.list_rules() if rid in ("L2-TYPO-001", "L2-DEPC-001", "L2-ADV-001")]
        assert len(shared_rules) == 3
        assert "L2-TYPO-001" in shared_rules
        assert "L2-DEPC-001" in shared_rules
        assert "L2-ADV-001" in shared_rules


# ── NuGet Typosquat ────────────────────────────────────────────────────


class TestNuGetTyposquat:
    """NuGet typosquat detection should flag suspicious package IDs."""

    def test_detects_typosquat_in_malicious(self):
        from picosentry.scan.rules.typosquat import detect_all_typosquat as detect_nuget_typosquat
        findings = detect_nuget_typosquat(_nuget_malicious(), FIXTURES.parent.parent / "picosentry" / "scan" / "corpus")
        typo_findings = [f for f in findings if f.rule_id == "L2-NUGET-TYPO-001"]
        assert len(typo_findings) >= 1
        # "Nwetonsoft.Json" is edit distance 2 from "Newtonsoft.Json"
        assert any("Nwetonsoft" in f.package or "Nwetonsoft" in f.message for f in typo_findings)

    def test_clean_project_has_no_typosquats(self):
        from picosentry.scan.rules.typosquat import detect_all_typosquat as detect_nuget_typosquat
        findings = detect_nuget_typosquat(_nuget_clean(), FIXTURES.parent.parent / "picosentry" / "scan" / "corpus")
        typo_findings = [f for f in findings if f.rule_id == "L2-NUGET-TYPO-001"]
        assert len(typo_findings) == 0


# ── NuGet Dependency Confusion ─────────────────────────────────────────


class TestNuGetDependencyConfusion:
    """NuGet dep confusion detection should flag internal-looking deps."""

    def test_detects_dep_confusion_in_malicious(self):
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_nuget_dep_confusion
        findings = detect_nuget_dep_confusion(_nuget_malicious())
        depc_findings = [f for f in findings if f.rule_id == "L2-NUGET-DEPC-001"]
        assert len(depc_findings) >= 1
        assert any("Company.Internal.Lib" in f.package for f in depc_findings)

    def test_clean_project_has_no_dep_confusion(self):
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_nuget_dep_confusion
        findings = detect_nuget_dep_confusion(_nuget_clean())
        depc_findings = [f for f in findings if f.rule_id == "L2-NUGET-DEPC-001"]
        assert len(depc_findings) == 0

    def test_private_source_suppresses_finding(self, tmp_path):
        """If a private NuGet source is configured, internal-looking packages should not be flagged."""
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_nuget_dep_confusion
        csproj_path = tmp_path / "test.csproj"
        csproj_path.write_text("""<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Company.Internal.Lib" Version="1.0.0" />
  </ItemGroup>
</Project>""")
        nuget_path = tmp_path / "nuget.config"
        nuget_path.write_text("""<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="internal" value="https://pkgs.internal.example.com/nuget/v3/index.json" />
  </packageSources>
</configuration>""")
        findings = detect_nuget_dep_confusion(tmp_path)
        depc_findings = [f for f in findings if f.rule_id == "L2-NUGET-DEPC-001"]
        assert len(depc_findings) == 0


# ── NuGet .csproj parsing ─────────────────────────────────────────────


class TestNuGetParsing:
    """NuGet .csproj parsing should extract dependencies correctly."""

    def test_parse_csproj_package_references(self):
        from picosentry.scan.rules.nuget_utils import parse_csproj_file
        data = parse_csproj_file(_nuget_clean())
        assert data is not None
        refs = data.get("package_references", [])
        assert len(refs) == 3
        pkg_ids = {p[0] for p in refs}
        assert "Newtonsoft.Json" in pkg_ids
        assert "Serilog" in pkg_ids
        assert "xunit" in pkg_ids

    def test_parse_csproj_project_name(self):
        from picosentry.scan.rules.nuget_utils import parse_csproj_file
        data = parse_csproj_file(_nuget_clean())
        assert data is not None
        assert data["project_name"] == "MyApp"

    def test_parse_csproj_target_framework(self):
        from picosentry.scan.rules.nuget_utils import parse_csproj_file
        data = parse_csproj_file(_nuget_clean())
        assert data is not None
        assert data["target_framework"] == "net8.0"

    def test_parse_csproj_no_file_returns_none(self, tmp_path):
        from picosentry.scan.rules.nuget_utils import parse_csproj_file
        assert parse_csproj_file(tmp_path) is None


# ── NuGet Lockfile Parser ─────────────────────────────────────────────


class TestNuGetLockfileParser:
    """NuGet lockfile parser should dispatch by filename."""

    def test_parse_csproj_for_lock(self):
        from picosentry.scan.rules.nuget_lock_parser import parse_csproj_for_lock
        entries = parse_csproj_for_lock(_nuget_clean() / "test.csproj")
        assert len(entries) == 3
        entry_ids = {e[0] for e in entries}
        assert "Newtonsoft.Json" in entry_ids

    def test_parse_nuget_lock_from_json(self):
        from picosentry.scan.rules.nuget_lock_parser import parse_nuget_lock_for_lock
        entries = parse_nuget_lock_for_lock(_nuget_clean() / "packages.lock.json")
        assert len(entries) == 3

    def test_parse_nuget_lockfile_auto_detect(self):
        from picosentry.scan.rules.nuget_lock_parser import parse_nuget_lockfile
        entries = parse_nuget_lockfile(_nuget_clean() / "test.csproj")
        assert len(entries) == 3

    def test_parse_nuget_lockfile_packages_config(self, tmp_path):
        from picosentry.scan.rules.nuget_lock_parser import parse_nuget_lockfile
        pc_path = tmp_path / "packages.config"
        pc_path.write_text("""<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net8.0" />
</packages>""")
        entries = parse_nuget_lockfile(pc_path)
        assert len(entries) == 1
        assert entries[0][0] == "Newtonsoft.Json"

    def test_parse_nuget_lockfile_no_file_returns_empty(self, tmp_path):
        from picosentry.scan.rules.nuget_lock_parser import parse_nuget_lockfile
        assert parse_nuget_lockfile(tmp_path / "nonexistent.txt") == []


# ── NuGet Utilities ───────────────────────────────────────────────────


class TestNuGetUtils:
    """NuGet utility functions."""

    def test_get_nuget_dep_names_from_csproj(self):
        from picosentry.scan.rules.nuget_utils import get_nuget_dep_names, parse_csproj_file
        data = parse_csproj_file(_nuget_clean())
        assert data is not None
        names = get_nuget_dep_names(data)
        assert "Newtonsoft.Json" in names
        assert "Serilog" in names

    def test_detect_private_nuget_source_clean(self):
        from picosentry.scan.rules.nuget_utils import detect_private_nuget_source
        assert not detect_private_nuget_source(_nuget_clean())

    def test_detect_private_nuget_source_with_config(self, tmp_path):
        from picosentry.scan.rules.nuget_utils import detect_private_nuget_source
        nuget_path = tmp_path / "nuget.config"
        nuget_path.write_text("""<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="internal" value="https://pkgs.internal.example.com/nuget/v3/index.json" />
  </packageSources>
</configuration>""")
        assert detect_private_nuget_source(tmp_path)

    def test_collect_nuget_deps(self):
        from picosentry.scan.rules.nuget_utils import collect_nuget_deps
        deps = collect_nuget_deps(_nuget_clean())
        dep_ids = {d[0] for d in deps}
        assert "Newtonsoft.Json" in dep_ids
        assert "Serilog" in dep_ids


# ── Integration ────────────────────────────────────────────────────────


class TestNuGetIntegration:
    """Full engine integration tests."""

    def test_clean_project_no_findings(self):
        engine = create_default_engine()
        result = engine.scan(_nuget_clean())
        nuget_findings = [f for f in result.findings if "L2-NUGET" in f.rule_id]
        assert len(nuget_findings) == 0

    def test_malicious_project_has_findings(self):
        engine = create_default_engine()
        result = engine.scan(_nuget_malicious())
        nuget_findings = [f for f in result.findings if "L2-NUGET" in f.rule_id]
        assert len(nuget_findings) >= 2  # typosquat + dep confusion
        rule_ids = {f.rule_id for f in nuget_findings}
        assert "L2-NUGET-TYPO-001" in rule_ids
        assert "L2-NUGET-DEPC-001" in rule_ids

    def test_findings_have_nuget_ecosystem(self):
        from picosentry.scan.rules.typosquat import detect_all_typosquat as detect_nuget_typosquat
        findings = detect_nuget_typosquat(_nuget_malicious(), FIXTURES.parent.parent / "picosentry" / "scan" / "corpus")
        for f in findings:
            assert f.ecosystem == "nuget"

    def test_dep_confusion_findings_are_critical(self):
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_nuget_dep_confusion
        findings = detect_nuget_dep_confusion(_nuget_malicious())
        for f in findings:
            assert f.severity == Severity.CRITICAL
            assert f.ecosystem == "nuget"

    def test_npm_backward_compat_preserved(self, tmp_path):
        """Adding NuGet rules should not affect npm scans."""
        (tmp_path / "package.json").write_text("{}")
        engine = create_default_engine()
        result = engine.scan(tmp_path)
        nuget_findings = [f for f in result.findings if "L2-NUGET" in f.rule_id]
        assert len(nuget_findings) == 0

    def test_nuget_rules_skipped_when_no_csproj(self, tmp_path):
        """NuGet rules should be filtered out when no .csproj."""
        (tmp_path / "README.md").write_text("# just a readme")
        engine = create_default_engine()
        result = engine.scan(tmp_path)
        nuget_findings = [f for f in result.findings if "L2-NUGET" in f.rule_id]
        assert len(nuget_findings) == 0
