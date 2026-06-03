"""Tests for formatters — table, github, sarif, cyclonedx, ml_context."""

from __future__ import annotations

import json

from picosentry.sandbox.formatters.cyclonedx import format_cyclonedx
from picosentry.sandbox.formatters.github import format_github
from picosentry.sandbox.formatters.ml_context import format_ml_context
from picosentry.sandbox.formatters.sarif import format_sarif
from picosentry.sandbox.formatters.table import format_table
from picosentry.sandbox.l3.models import SandboxEvent, SandboxResult
from picosentry.sandbox.l4.models import AnalysisResult, BehavioralProfile, BehavioralVerdict
from picosentry.sandbox.models import Finding, Severity, Verdict


def _make_findings():
    return [
        Finding(
            rule_id="L3-NET-001", severity=Severity.HIGH, message="Network call detected", location="/tmp", evidence={}
        ),
        Finding(
            rule_id="L3-PROC-001",
            severity=Severity.CRITICAL,
            message="Process spawn",
            location="/usr/bin/sudo",
            evidence={},
        ),
    ]


def _make_sandbox_result():
    return SandboxResult(
        run_id="test-run",
        timestamp="2025-01-01T00:00:00Z",
        command=["echo", "hello"],
        overall_verdict=Verdict.ALLOW,
        exit_code=0,
        duration_ms=100,
        events=[
            SandboxEvent(rule_id="L3-NET-001", verdict=Verdict.DENY, operation="network_out", detail="curl detected"),
        ],
        policy_name="test-policy",
        stdout="hello",
        stderr="",
    )


def _make_analysis_result():
    return AnalysisResult(
        target="test-pkg",
        findings=_make_findings(),
        overall_verdict=BehavioralVerdict.SUSPICIOUS,
        profile=BehavioralProfile(
            package="test-pkg",
            entrypoint="main",
            total_runtime_ms=100,
            exit_code=0,
            stdout_len=10,
            stderr_len=0,
        ),
    )


class TestTableFormatter:
    def test_format_sandbox(self):
        result = _make_sandbox_result()
        output = format_table(result)
        assert isinstance(output, str)
        assert len(output) > 0

    def test_format_analysis(self):
        result = _make_analysis_result()
        output = format_table(result)
        assert isinstance(output, str)

    def test_format_empty_sandbox(self):
        result = SandboxResult(
            run_id="test",
            timestamp="2025-01-01",
            command=["echo"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=100,
            events=[],
            policy_name="test",
            stdout="",
            stderr="",
        )
        output = format_table(result)
        assert isinstance(output, str)


class TestGitHubFormatter:
    def test_format_sandbox(self, tmp_path):
        result = _make_sandbox_result()
        output = format_github(result, sarif_path=str(tmp_path / "test.sarif"))
        assert isinstance(output, str)

    def test_format_analysis(self, tmp_path):
        result = _make_analysis_result()
        output = format_github(result, sarif_path=str(tmp_path / "test.sarif"))
        assert isinstance(output, str)


class TestSarifFormatter:
    def test_format_sandbox(self):
        result = _make_sandbox_result()
        output = format_sarif(result)
        data = json.loads(output)
        assert "$schema" in data
        assert "runs" in data

    def test_format_analysis(self):
        result = _make_analysis_result()
        output = format_sarif(result)
        data = json.loads(output)
        assert "runs" in data


class TestCycloneDXFormatter:
    def test_format_sandbox(self):
        result = _make_sandbox_result()
        output = format_cyclonedx(result)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_format_analysis(self):
        result = _make_analysis_result()
        output = format_cyclonedx(result)
        assert isinstance(output, str)
        assert len(output) > 0


class TestMLContextFormatter:
    def test_format_sandbox(self):
        result = _make_sandbox_result()
        output = format_ml_context(result, token_budget=4096)
        assert isinstance(output, str)
        assert "PICODOME" in output or "echo" in output

    def test_format_analysis(self):
        result = _make_analysis_result()
        output = format_ml_context(result, token_budget=4096)
        assert isinstance(output, str)
        assert len(output) > 0

    def test_token_budget(self):
        result = _make_analysis_result()
        output = format_ml_context(result, token_budget=100)
        assert isinstance(output, str)
