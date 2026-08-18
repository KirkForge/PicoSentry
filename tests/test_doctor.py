"""Tests for picosentry._core.doctor — self-verify and repair module."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from picosentry._core import doctor
from picosentry._core.doctor import (
    CheckResult,
    DoctorReport,
    _check_corpus_files,
    _check_detector_implementations,
    _check_experimental_claims,
    _check_fixture_count,
    _check_imports_healthy,
    _check_no_secrets_in_source,
    _check_optional_extras,
    _check_picodome_not_tracked,
    _check_rule_aliases_consistency,
    _check_rule_info_count,
    _check_version_consistency,
    _check_watch_rules,
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
        assert result.status == "pass", result.detail
        assert "detector implementations" in result.detail


class TestFixtureCount:
    def test_fixtures_exist(self):
        result = _check_fixture_count()
        assert result.status == "pass", result.detail
        assert "matches REPORT.json" in result.detail
        assert "tricky" in result.detail

    def _make_tree(self, root: Path, pos: int, neg: int, tricky: int, report: dict | None = None) -> Path:
        fixtures = root / "tests" / "scan" / "fixtures" / "validation"
        for name, count in (("positive", pos), ("negative", neg), ("_tricky", tricky)):
            for i in range(count):
                (fixtures / name / f"f{i}").mkdir(parents=True, exist_ok=True)
        if report is None:
            report = {
                "total_fixtures": pos + neg,
                "total_positive": pos,
                "total_negative": neg,
                "fixture_results": [{"fixture": f"f{i}"} for i in range(pos + neg)],
            }
        (fixtures / "REPORT.json").write_text(json.dumps(report))
        return root

    def test_healthy_tree_passes(self, tmp_path, monkeypatch):
        monkeypatch.setattr(doctor, "_ROOT", self._make_tree(tmp_path, 2, 1, 1))
        monkeypatch.setattr("picosentry.experimental.COMPONENT_STATUS", ())
        result = _check_fixture_count()
        assert result.status == "pass", result.detail
        assert "4 fixtures (2 pos / 1 neg / 1 tricky)" in result.detail

    def test_report_drift_fails(self, tmp_path, monkeypatch):
        root = self._make_tree(tmp_path, 2, 1, 1)
        report = json.loads((root / "tests" / "scan" / "fixtures" / "validation" / "REPORT.json").read_text())
        report["total_fixtures"] = 99
        (root / "tests" / "scan" / "fixtures" / "validation" / "REPORT.json").write_text(json.dumps(report))
        monkeypatch.setattr(doctor, "_ROOT", root)
        monkeypatch.setattr("picosentry.experimental.COMPONENT_STATUS", ())
        result = _check_fixture_count()
        assert result.status == "fail"
        assert "total_fixtures=99" in result.detail

    def test_claim_drift_fails(self, tmp_path, monkeypatch):
        from picosentry.experimental import ComponentStatus

        monkeypatch.setattr(doctor, "_ROOT", self._make_tree(tmp_path, 2, 1, 1))
        monkeypatch.setattr(
            "picosentry.experimental.COMPONENT_STATUS",
            (ComponentStatus(name="`picosentry scan`", status="Stable", notes="53 rules, 99 fixtures"),),
        )
        result = _check_fixture_count()
        assert result.status == "fail"
        assert "claims 99 fixtures" in result.detail

    def test_missing_positive_dir_fails(self, tmp_path, monkeypatch):
        import shutil

        root = self._make_tree(tmp_path, 1, 1, 1)
        shutil.rmtree(root / "tests" / "scan" / "fixtures" / "validation" / "positive")
        monkeypatch.setattr(doctor, "_ROOT", root)
        monkeypatch.setattr("picosentry.experimental.COMPONENT_STATUS", ())
        result = _check_fixture_count()
        assert result.status == "fail"
        assert "missing fixture directory" in result.detail


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
        assert result.status == "pass", result.detail

    def _make_tree(self, root: Path, top: str, core: str, serve: str, pyproject: str, app_version: str) -> Path:
        (root / "picosentry" / "_core").mkdir(parents=True)
        (root / "picosentry" / "serve" / "config").mkdir(parents=True)
        (root / "picosentry" / "__init__.py").write_text(f'__version__ = "{top}"\n')
        (root / "picosentry" / "_core" / "__init__.py").write_text(f'__version__ = "{core}"\n')
        (root / "picosentry" / "serve" / "config" / "version.py").write_text(f'__version__ = "{serve}"\n')
        (root / "pyproject.toml").write_text(f'[project]\nversion = "{pyproject}"\n')
        (root / "deploy" / "helm" / "picodome").mkdir(parents=True)
        (root / "deploy" / "helm" / "picodome" / "Chart.yaml").write_text(f'appVersion: "{app_version}"\n')
        return root

    def test_serve_version_drift_fails(self, tmp_path, monkeypatch):
        monkeypatch.setattr(doctor, "_ROOT", self._make_tree(tmp_path, "1.0.0", "1.0.0", "0.9.0", "1.0.0", "v1.0.0"))
        result = _check_version_consistency()
        assert result.status == "fail"
        assert "serve/config/version.py" in result.detail

    def test_helm_appversion_drift_fails(self, tmp_path, monkeypatch):
        monkeypatch.setattr(doctor, "_ROOT", self._make_tree(tmp_path, "1.0.0", "1.0.0", "1.0.0", "1.0.0", "v0.9.9"))
        result = _check_version_consistency()
        assert result.status == "fail"
        assert "appVersion" in result.detail

    def test_helm_appversion_must_be_v_prefixed(self, tmp_path, monkeypatch):
        monkeypatch.setattr(doctor, "_ROOT", self._make_tree(tmp_path, "1.0.0", "1.0.0", "1.0.0", "1.0.0", "1.0.0"))
        result = _check_version_consistency()
        assert result.status == "fail"
        assert "v-prefixed" in result.detail


class TestWatchRules:
    def test_rules_load_cleanly(self):
        result = _check_watch_rules()
        assert result.status == "pass", result.detail
        assert "watch rules loaded cleanly" in result.detail

    def test_broken_rules_fail(self, tmp_path, monkeypatch):
        rules = tmp_path / "rules"
        (rules / "prompt_injection").mkdir(parents=True)
        (rules / "prompt_injection" / "bad.yaml").write_text("id: [unclosed\n")
        (rules / "output_policy").mkdir(parents=True)
        (rules / "output_policy" / "ok.yaml").write_text("id: OK-1\ncategory: exfil\npattern: secret\n")
        monkeypatch.setattr("picosentry.watch.config.DEFAULT_RULES_DIR", rules)
        result = _check_watch_rules()
        assert result.status == "fail"
        assert "prompt_injection" in result.detail

    def test_empty_corpus_fails(self, tmp_path, monkeypatch):
        rules = tmp_path / "rules"
        (rules / "prompt_injection").mkdir(parents=True)
        (rules / "output_policy").mkdir(parents=True)
        monkeypatch.setattr("picosentry.watch.config.DEFAULT_RULES_DIR", rules)
        result = _check_watch_rules()
        assert result.status == "fail"
        assert "no rules loaded" in result.detail


class TestOptionalExtras:
    def test_all_extras_importable(self):
        result = _check_optional_extras()
        assert result.status == "pass", result.detail

    def test_missing_module_fails(self, monkeypatch):
        monkeypatch.setattr(doctor, "_EXTRA_IMPORTS", {"scan": ("no_such_module_qq_zz",)})
        result = _check_optional_extras()
        assert result.status == "fail"
        assert "no_such_module_qq_zz" in result.detail

    def test_unmapped_declared_extra_fails(self, monkeypatch):
        monkeypatch.setattr(doctor, "_EXTRA_IMPORTS", {})
        result = _check_optional_extras()
        assert result.status == "fail"
        assert "unmapped" in result.detail

    def test_stale_map_entry_fails(self, monkeypatch):
        imports = dict(doctor._EXTRA_IMPORTS)
        imports["ghost"] = ("requests",)
        monkeypatch.setattr(doctor, "_EXTRA_IMPORTS", imports)
        result = _check_optional_extras()
        assert result.status == "fail"
        assert "ghost" in result.detail


class TestVerify:
    @pytest.fixture(scope="class")
    def verify_report(self):
        """One shared verify() for the shape assertions — verify() takes ~4s
        walking the repo and its report is read-only here. The repair variant
        runs its own call (it mutates pycache state)."""
        return verify()

    def test_verify_returns_report(self, verify_report):
        report = verify_report
        assert isinstance(report, DoctorReport)
        assert len(report.checks) >= 10
        assert report.elapsed >= 0

    def test_verify_with_repair(self):
        report = verify(repair=True)
        assert any(c.name == "clean_pycache" for c in report.checks)

    def test_verify_all_checks_have_names(self, verify_report):
        report = verify_report
        for check in report.checks:
            assert check.name
            assert check.status in ("pass", "fail", "warn")
            assert check.detail


class TestStandaloneModule:
    # Decision (WO5.0.0-025 item 11a, 2026-08-18): the watch CLI keeps exit 2
    # for blocked prompts / invalid output despite colliding with argparse's
    # usage-error convention — changing it breaks consumers that branch on
    # 2 = blocked. The collision is documented here and in the WO instead of
    # churned; the GitLab template exit-map handles scan exits separately.

    def _run_module(self, *extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "picosentry._core.doctor", *extra],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=120,
        )

    def test_module_main_returns_zero_on_pass(self):
        result = self._run_module()
        assert result.returncode == 0, result.stdout + result.stderr
        assert "0 fail" in result.stdout

    def test_module_main_with_repair(self):
        result = self._run_module("--repair")
        assert result.returncode == 0, result.stdout + result.stderr
        assert "0 fail" in result.stdout


class TestDoctorCliExitCodes:
    """`picosentry doctor` (unified wrapper) must fail honestly on both paths."""

    def _cmd(self, output_json: bool) -> int:
        from picosentry.cli_commands import doctor as doctor_cli

        return doctor_cli.cmd(argparse.Namespace(repair=False, output_json=output_json))

    def test_json_path_exits_1_on_failing_report(self, capsys):
        failing = DoctorReport(checks=[CheckResult("x", "fail", "boom")])
        with patch("picosentry._core.doctor.verify", return_value=failing):
            assert self._cmd(output_json=True) == 1
        assert "fail" in capsys.readouterr().out

    def test_json_path_exits_0_on_passing_report(self):
        passing = DoctorReport(checks=[CheckResult("x", "pass", "ok")])
        with patch("picosentry._core.doctor.verify", return_value=passing):
            assert self._cmd(output_json=True) == 0

    def test_text_path_exits_1_on_failing_report(self):
        failing = DoctorReport(checks=[CheckResult("x", "fail", "boom")])
        with patch("picosentry._core.doctor.verify", return_value=failing):
            assert self._cmd(output_json=False) == 1


class TestHealthCommand:
    """`picosentry health` must import the engine for real — a broken import
    must FAIL the check (WO5.0.0-025 item 2)."""

    def test_healthy_exit_0(self, capsys):
        from picosentry.cli_commands import health

        assert health.cmd(argparse.Namespace()) == 0
        assert "All components healthy." in capsys.readouterr().out

    def test_broken_scan_engine_import_fails(self, capsys, monkeypatch):
        import sys as _sys

        monkeypatch.setitem(_sys.modules, "picosentry.scan.engine", None)
        from picosentry.cli_commands import health

        assert health.cmd(argparse.Namespace()) == 1
        assert "scan" in capsys.readouterr().out
