"""
test_engine.py — Tests for L2-ENGIN-001 engine constraint detection.
"""


from picosentry.scan.engine import create_default_engine
from picosentry.scan.models import Severity
from picosentry.scan.rules.engine import detect_engine_issues

from tests.scan.conftest import make_npm_project as _make_project


class TestEngineConstraints:
    """Test L2-ENGIN-001 engine constraint detection."""

    def test_no_engines_no_scripts(self, tmp_path):
        """Missing engines with no scripts → LOW."""
        project = _make_project(
            tmp_path,
            {
                "name": "no-engines",
                "version": "1.0.0",
            },
        )
        findings = detect_engine_issues(project)
        assert any(f.rule_id == "L2-ENGIN-001" and f.severity == Severity.LOW for f in findings)

    def test_no_engines_with_install_scripts(self, tmp_path):
        """Missing engines + install scripts → HIGH (runs on any Node)."""
        project = _make_project(
            tmp_path,
            {
                "name": "no-engines-scripts",
                "version": "1.0.0",
                "scripts": {"postinstall": "node build.js"},
            },
        )
        findings = detect_engine_issues(project)
        assert any(f.rule_id == "L2-ENGIN-001" and f.severity == Severity.HIGH for f in findings)

    def test_overly_permissive_engines_star(self, tmp_path):
        """engines.node = '*' → MEDIUM (overly permissive)."""
        project = _make_project(
            tmp_path,
            {
                "name": "star-engines",
                "version": "1.0.0",
                "engines": {"node": "*"},
            },
        )
        findings = detect_engine_issues(project)
        assert any(f.rule_id == "L2-ENGIN-001" and f.severity == Severity.MEDIUM for f in findings)

    def test_overly_permissive_engines_gte_000(self, tmp_path):
        """engines.node = '>=0.0.0' → MEDIUM."""
        project = _make_project(
            tmp_path,
            {
                "name": "gte-zero",
                "version": "1.0.0",
                "engines": {"node": ">=0.0.0"},
            },
        )
        findings = detect_engine_issues(project)
        assert any(f.rule_id == "L2-ENGIN-001" and f.severity == Severity.MEDIUM for f in findings)

    def test_overly_permissive_engines_any(self, tmp_path):
        """engines.node = 'any' → MEDIUM."""
        project = _make_project(
            tmp_path,
            {
                "name": "any-engines",
                "version": "1.0.0",
                "engines": {"node": "any"},
            },
        )
        findings = detect_engine_issues(project)
        assert any(f.rule_id == "L2-ENGIN-001" and f.severity == Severity.MEDIUM for f in findings)

    def test_narrow_engines_exact(self, tmp_path):
        """engines.node = '18.17.0' (exact pin) → INFO."""
        project = _make_project(
            tmp_path,
            {
                "name": "exact-pin",
                "version": "1.0.0",
                "engines": {"node": "18.17.0"},
            },
        )
        findings = detect_engine_issues(project)
        assert any(f.rule_id == "L2-ENGIN-001" and f.severity == Severity.INFO for f in findings)

    def test_reasonable_engines_range(self, tmp_path):
        """engines.node = '>=18.0.0' → no findings (reasonable constraint)."""
        project = _make_project(
            tmp_path,
            {
                "name": "reasonable-engines",
                "version": "1.0.0",
                "engines": {"node": ">=18.0.0"},
            },
        )
        findings = detect_engine_issues(project)
        assert not any(f.rule_id == "L2-ENGIN-001" for f in findings)

    def test_npm_without_node(self, tmp_path):
        """engines with npm but no node → LOW (incomplete constraint)."""
        project = _make_project(
            tmp_path,
            {
                "name": "npm-only",
                "version": "1.0.0",
                "engines": {"npm": ">=8.0.0"},
            },
        )
        findings = detect_engine_issues(project)
        assert any(f.rule_id == "L2-ENGIN-001" and f.severity == Severity.LOW for f in findings)

    def test_npm_with_node(self, tmp_path):
        """engines with both node and npm → no npm-only finding."""
        project = _make_project(
            tmp_path,
            {
                "name": "both-engines",
                "version": "1.0.0",
                "engines": {"node": ">=18.0.0", "npm": ">=8.0.0"},
            },
        )
        findings = detect_engine_issues(project)
        # Should NOT have the npm-without-node finding
        assert not any("npm without node" in f.evidence.lower() for f in findings if f.rule_id == "L2-ENGIN-001")

    def test_empty_engines_object(self, tmp_path):
        """engines: {} → treated as missing (no constraint)."""
        project = _make_project(
            tmp_path,
            {
                "name": "empty-engines",
                "version": "1.0.0",
                "engines": {},
            },
        )
        findings = detect_engine_issues(project)
        assert any(f.rule_id == "L2-ENGIN-001" for f in findings)

    def test_deterministic_engine_findings(self, tmp_path):
        """Same project scanned twice produces identical findings."""
        project = _make_project(
            tmp_path,
            {
                "name": "det-test",
                "version": "1.0.0",
                "scripts": {"postinstall": "echo hi"},
            },
        )
        findings_a = detect_engine_issues(project)
        findings_b = detect_engine_issues(project)
        assert len(findings_a) == len(findings_b)
        for a, b in zip(findings_a, findings_b, strict=False):
            assert a.rule_id == b.rule_id
            assert a.severity == b.severity
            assert a.package == b.package
            assert a.evidence == b.evidence

    def test_engine_rule_in_full_scan(self, tmp_path):
        """L2-ENGIN-001 is registered and runs in full engine scan."""
        project = _make_project(
            tmp_path,
            {
                "name": "full-scan-engines",
                "version": "1.0.0",
                "scripts": {"postinstall": "node setup.js"},
            },
        )
        engine = create_default_engine()
        result = engine.scan(project)
        engine_findings = [f for f in result.findings if f.rule_id == "L2-ENGIN-001"]
        assert len(engine_findings) >= 1
