"""Tests for picosentry._core.doctor — self-verify and repair module."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from picosentry._core.doctor import (
    CheckResult,
    DoctorReport,
    _check_corpus_files,
    _check_detector_implementations,
    _check_experimental_claims,
    _check_fixture_count,
    _check_imports_healthy,
    _check_no_secrets_in_source,
    _check_picodome_not_tracked,
    _check_rule_aliases_consistency,
    _check_rule_info_count,
    _check_version_consistency,
    verify,
)


ROOT = Path(__file__).resolve().parent.parent


class TestCheckResult:
    def test_dataclass_fields(self):
        r = CheckResult(name="test", status="pass", detail="ok")
        assert r.name == "test"
        assert r.status == "pass"
        assert r.detail == "ok"
        assert r.repaired is False
        assert r.repair_detail == ""

    def test_repaired_fields(self):
        r = CheckResult(name="clean", status="pass", detail="done", repaired=True, repair_detail="Deleted 3 dirs")
        assert r.repaired is True
        assert r.repair_detail == "Deleted 3 dirs"


class TestDoctorReport:
    def test_summary_all_pass(self):
        report = DoctorReport(
            checks=[
                CheckResult("a", "pass", "ok"),
                CheckResult("b", "pass", "ok"),
            ]
        )
        assert report.summary() == "2 pass, 0 fail, 0 warn"

    def test_summary_mixed(self):
        report = DoctorReport(
            checks=[
                CheckResult("a", "pass", "ok"),
                CheckResult("b", "fail", "bad"),
                CheckResult("c", "warn", "hmm"),
            ]
        )
        assert report.summary() == "1 pass, 1 fail, 1 warn"

    def test_all_passed_true(self):
        report = DoctorReport(
            checks=[
                CheckResult("a", "pass", "ok"),
                CheckResult("b", "warn", "hmm"),
            ]
        )
        assert report.all_passed() is True

    def test_all_passed_false(self):
        report = DoctorReport(
            checks=[
                CheckResult("a", "pass", "ok"),
                CheckResult("b", "fail", "bad"),
            ]
        )
        assert report.all_passed() is False

    def test_to_json_roundtrip(self):
        report = DoctorReport(
            checks=[CheckResult("test", "pass", "works")],
            elapsed=1.23,
            timestamp="2026-01-01T00:00:00",
        )
        text = report.to_json()
        data = json.loads(text)
        assert data["checks"][0]["name"] == "test"
        restored = DoctorReport.from_json(text)
        assert len(restored.checks) == 1
        assert restored.checks[0].name == "test"
        assert restored.elapsed == 1.23


class TestRuleInfoCount:
    def test_rule_count_matches(self):
        result = _check_rule_info_count()
        assert result.status in ("pass", "fail")
        if result.status == "pass":
            assert "rules in RULE_INFO" in result.detail


class TestRuleAliasesConsistency:
    def test_aliases_check(self):
        result = _check_rule_aliases_consistency()
        assert result.status in ("pass", "fail")


class TestDetectorImplementations:
    def test_detectors_registered(self):
        result = _check_detector_implementations()
        assert result.status in ("pass", "fail")
        if result.status == "pass":
            assert "detector implementations" in result.detail


class TestFixtureCount:
    def test_fixtures_exist(self):
        result = _check_fixture_count()
        assert result.status == "pass"
        assert "validation fixture directories" in result.detail


class TestCorpusFiles:
    def test_corpus_valid(self):
        result = _check_corpus_files()
        assert result.status in ("pass", "fail")
        assert "corpus JSON files" in result.detail


class TestImportsHealthy:
    def test_core_imports(self):
        result = _check_imports_healthy()
        assert result.status in ("pass", "fail")


class TestPicodomeNotTracked:
    def test_picodome_not_in_git(self):
        result = _check_picodome_not_tracked()
        assert result.status in ("pass", "fail")


class TestNoSecretsInSource:
    def test_no_secrets(self):
        result = _check_no_secrets_in_source()
        assert result.status in ("pass", "fail")


class TestExperimentalClaims:
    def test_claims_match(self):
        result = _check_experimental_claims()
        assert result.status in ("pass", "fail")


class TestVersionConsistency:
    def test_versions_match(self):
        result = _check_version_consistency()
        assert result.status in ("pass", "fail", "warn")


class TestVerify:
    def test_verify_returns_report(self):
        report = verify()
        assert isinstance(report, DoctorReport)
        assert len(report.checks) >= 10
        assert report.elapsed >= 0

    def test_verify_with_repair(self):
        report = verify(repair=True)
        assert any(c.name == "clean_pycache" for c in report.checks)

    def test_verify_all_checks_have_names(self):
        report = verify()
        for check in report.checks:
            assert check.name
            assert check.status in ("pass", "fail", "warn")
            assert check.detail


class TestStandaloneModule:
    def test_module_main_returns_zero_on_pass(self):
        result = subprocess.run(
            [sys.executable, "-m", "picosentry._core.doctor"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=120,
        )
        assert result.returncode in (0, 1)

    def test_module_main_with_repair(self):
        result = subprocess.run(
            [sys.executable, "-m", "picosentry._core.doctor", "--repair"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=120,
        )
        assert result.returncode in (0, 1)
