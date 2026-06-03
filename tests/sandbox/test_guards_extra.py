"""Extra guards tests — DeterministicGuard, validate_findings, diff_results, deterministic_hash."""

from __future__ import annotations

import json

import pytest

from picosentry.sandbox.guards import (
    DeterminismViolation,
    DeterministicGuard,
    deterministic_hash,
    diff_results,
    validate_findings_deterministic,
)
from picosentry.sandbox.l3.models import SandboxEvent, SandboxResult, Verdict
from picosentry.sandbox.l4.models import AnalysisResult, BehavioralProfile, BehavioralVerdict
from picosentry.sandbox.models import Finding, Severity


def _make_sandbox_result(**overrides):
    defaults = {
        "run_id": "",
        "timestamp": "",
        "command": ["echo", "hello"],
        "overall_verdict": Verdict.ALLOW,
        "exit_code": 0,
        "duration_ms": 100,
        "events": [],
        "policy_name": "test",
        "stdout": "hello",
        "stderr": "",
    }
    defaults.update(overrides)
    return SandboxResult(**defaults)


def _make_analysis_result(**overrides):
    defaults = {
        "target": "test-pkg",
        "findings": [],
        "overall_verdict": BehavioralVerdict.CLEAN,
        "profile": BehavioralProfile(
            package="test-pkg", entrypoint="main", total_runtime_ms=100, exit_code=0, stdout_len=10, stderr_len=0
        ),
    }
    defaults.update(overrides)
    return AnalysisResult(**defaults)


# ─── DeterministicGuard ─────────────────────────────────────────────


class TestDeterministicGuard:
    def test_clean_sandbox_result(self):
        guard = DeterministicGuard()
        result = _make_sandbox_result()
        violations = guard.check(result)
        assert violations == []

    def test_clean_analysis_result(self):
        guard = DeterministicGuard()
        result = _make_analysis_result()
        violations = guard.check(result)
        assert violations == []

    def test_uuid_run_id(self):
        guard = DeterministicGuard()
        result = _make_sandbox_result(run_id="550e8400-e29b-41d4-a716-446655440000")
        violations = guard.check(result)
        assert any("run_id" in v for v in violations)

    def test_timestamp_violation(self):
        guard = DeterministicGuard()
        result = _make_sandbox_result(timestamp="2025-01-15T10:30:00Z")
        violations = guard.check(result)
        assert any("timestamp" in v for v in violations)

    def test_event_with_uuid(self):
        guard = DeterministicGuard()
        event = SandboxEvent(
            rule_id="L3-NET-001",
            verdict=Verdict.DENY,
            operation="net",
            detail="uuid 550e8400-e29b-41d4-a716-446655440000 found",
        )
        result = _make_sandbox_result(events=[event])
        violations = guard.check(result)
        assert any("UUID" in v for v in violations)

    def test_assert_deterministic_raises(self):
        guard = DeterministicGuard()
        result = _make_sandbox_result(timestamp="2025-01-15T10:30:00Z")
        with pytest.raises(DeterminismViolation):
            guard.assert_deterministic(result)

    def test_assert_deterministic_passes(self):
        guard = DeterministicGuard()
        result = _make_sandbox_result()
        guard.assert_deterministic(result)  # no raise


class TestValidateFindingsDeterministic:
    def test_clean_findings(self):
        findings = [Finding(rule_id="R1", severity=Severity.HIGH, message="clean", location="/tmp", evidence={})]
        violations = validate_findings_deterministic(findings)
        assert violations == []

    def test_finding_with_uuid_in_evidence(self):
        findings = [
            Finding(
                rule_id="R1",
                severity=Severity.HIGH,
                message="found uuid",
                location="/tmp",
                evidence={"uuid": "550e8400-e29b-41d4-a716-446655440000"},
            )
        ]
        violations = validate_findings_deterministic(findings)
        assert len(violations) > 0

    def test_finding_with_timestamp(self):
        findings = [
            Finding(
                rule_id="R1", severity=Severity.HIGH, message="2025-01-15T10:30:00Z found", location="/tmp", evidence={}
            )
        ]
        violations = validate_findings_deterministic(findings)
        assert len(violations) > 0


# ─── diff_results ──────────────────────────────────────────────────


class TestDiffResults:
    def test_identical_results(self, tmp_path):
        data = {"findings": [], "verdict": "allow", "duration_ms": 100, "run_id": "", "timestamp": ""}
        path_a = tmp_path / "a.json"
        path_b = tmp_path / "b.json"
        path_a.write_text(json.dumps(data, sort_keys=True))
        path_b.write_text(json.dumps(data, sort_keys=True))
        exit_code, msg = diff_results(path_a, path_b)
        assert exit_code == 0
        assert "IDENTICAL" in msg

    def test_different_results(self, tmp_path):
        data_a = {"findings": [], "verdict": "allow", "duration_ms": 100, "run_id": "", "timestamp": ""}
        data_b = {
            "findings": [{"rule_id": "X", "message": "Y"}],
            "verdict": "deny",
            "duration_ms": 200,
            "run_id": "",
            "timestamp": "",
        }
        path_a = tmp_path / "a.json"
        path_b = tmp_path / "b.json"
        path_a.write_text(json.dumps(data_a, sort_keys=True))
        path_b.write_text(json.dumps(data_b, sort_keys=True))
        exit_code, msg = diff_results(path_a, path_b)
        assert exit_code == 1
        assert "DIFFER" in msg

    def test_missing_file_a(self, tmp_path):
        path_a = tmp_path / "nonexistent.json"
        path_b = tmp_path / "b.json"
        path_b.write_text("{}")
        exit_code, msg = diff_results(path_a, path_b)
        assert exit_code == 2

    def test_missing_file_b(self, tmp_path):
        path_a = tmp_path / "a.json"
        path_b = tmp_path / "nonexistent.json"
        path_a.write_text("{}")
        exit_code, msg = diff_results(path_a, path_b)
        assert exit_code == 2

    def test_invalid_json(self, tmp_path):
        path_a = tmp_path / "a.json"
        path_b = tmp_path / "b.json"
        path_a.write_text("not json at all")
        path_b.write_text("{}")
        exit_code, msg = diff_results(path_a, path_b)
        assert exit_code == 2

    def test_verbose_diff(self, tmp_path):
        data_a = {"findings": [{"rule_id": "R1", "message": "old"}], "verdict": "allow", "run_id": "", "timestamp": ""}
        data_b = {"findings": [{"rule_id": "R2", "message": "new"}], "verdict": "deny", "run_id": "", "timestamp": ""}
        path_a = tmp_path / "a.json"
        path_b = tmp_path / "b.json"
        path_a.write_text(json.dumps(data_a, sort_keys=True))
        path_b.write_text(json.dumps(data_b, sort_keys=True))
        exit_code, msg = diff_results(path_a, path_b, verbose=True)
        assert exit_code == 1
        assert "Removed" in msg or "Added" in msg

    def test_timing_only_difference(self, tmp_path):
        data_a = {"findings": [], "verdict": "allow", "duration_ms": 100, "run_id": "", "timestamp": ""}
        data_b = {"findings": [], "verdict": "allow", "duration_ms": 200, "run_id": "", "timestamp": ""}
        path_a = tmp_path / "a.json"
        path_b = tmp_path / "b.json"
        path_a.write_text(json.dumps(data_a, sort_keys=True))
        path_b.write_text(json.dumps(data_b, sort_keys=True))
        exit_code, msg = diff_results(path_a, path_b)
        assert exit_code == 0  # deterministic fields match


# ─── deterministic_hash ─────────────────────────────────────────────


class TestDeterministicHash:
    def test_same_result_same_hash(self):
        result = _make_sandbox_result()
        h1 = deterministic_hash(result)
        h2 = deterministic_hash(result)
        assert h1 == h2

    def test_different_timing_same_hash(self):
        r1 = _make_sandbox_result(duration_ms=100)
        r2 = _make_sandbox_result(duration_ms=200)
        assert deterministic_hash(r1) == deterministic_hash(r2)

    def test_different_findings_different_hash(self):
        r1 = _make_sandbox_result(overall_verdict=Verdict.ALLOW)
        r2 = _make_sandbox_result(overall_verdict=Verdict.DENY)
        assert deterministic_hash(r1) != deterministic_hash(r2)
