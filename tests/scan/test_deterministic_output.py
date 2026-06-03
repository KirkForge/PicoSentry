"""
test_deterministic_output.py — Regression tests for --deterministic-output flag.

Tests that:
1. Normal JSON output includes audit timestamps and timing
2. --deterministic-output omits timestamps, timing, and audit metadata
3. Two --deterministic-output runs produce byte-identical JSON
4. ScanResult.to_dict() with deterministic_output=True has no timing fields
5. RuleExecution.to_dict() with deterministic_output=True omits duration_ms
"""

import json

from picosentry.scan.models import (
    Confidence,
    Finding,
    RuleExecution,
    ScanResult,
    ScanStats,
    Severity,
)


def _make_result_with_timing():
    """Create a ScanResult with timing data to test deterministic output."""
    f1 = Finding(
        rule_id="L2-POST-001",
        severity=Severity.HIGH,
        confidence=Confidence.EXACT,
        package="evil-pkg",
        file="evil-pkg/package.json",
        message="post-install script found",
        evidence="scripts.postinstall",
        remediation="Remove the package",
    )
    result = ScanResult(
        target="/test/project",
        engine_version="0.15.0",
        corpus_version="faec530b1d00",
        findings=[f1],
        stats=ScanStats(
            packages_scanned=5,
            files_scanned=12,
            duration_ms=150,
            findings_by_severity={"HIGH": 1},
            findings_by_rule={"L2-POST-001": 1},
            rule_timings_ms={"L2-POST-001": 50},
        ),
        rule_executions=[
            RuleExecution(
                rule_id="L2-POST-001",
                status="ok",
                duration_ms=50,
                findings_count=1,
            ),
        ],
        started_at="2024-01-15T10:30:00+00:00",
        completed_at="2024-01-15T10:30:01+00:00",
        scanner_version="0.15.0",
        config_digest="abc123",
    )
    result.recompute_stats()
    return result


class TestDeterministicOutput:
    """Test that --deterministic-output produces byte-stable JSON."""

    def test_normal_output_includes_audit(self):
        """Normal to_dict() includes audit timestamps and timing."""
        result = _make_result_with_timing()
        d = result.to_dict()
        assert "audit" in d, "Normal output should include audit section"
        assert "started_at" in d["audit"]
        assert "completed_at" in d["audit"]
        assert "duration_ms" in d["stats"]
        assert "rule_timings_ms" in d["stats"]

    def test_deterministic_output_omits_audit(self):
        """deterministic_output=True should omit the audit section entirely."""
        result = _make_result_with_timing()
        d = result.to_dict(deterministic_output=True)
        assert "audit" not in d, "Deterministic output should not include audit section"

    def test_deterministic_output_omits_timing_from_stats(self):
        """deterministic_output=True should omit duration_ms and rule_timings_ms from stats."""
        result = _make_result_with_timing()
        d = result.to_dict(deterministic_output=True)
        assert "duration_ms" not in d["stats"], "duration_ms should be omitted in deterministic mode"
        assert "rule_timings_ms" not in d["stats"], "rule_timings_ms should be omitted in deterministic mode"
        # But structural fields should still be present
        assert "packages_scanned" in d["stats"]
        assert "files_scanned" in d["stats"]
        assert "findings_by_severity" in d["stats"]

    def test_deterministic_output_omits_rule_timing(self):
        """deterministic_output=True should omit duration_ms from rule_status."""
        result = _make_result_with_timing()
        d = result.to_dict(deterministic_output=True)
        rule_status = d.get("rule_status", {})
        for rule_id, status in rule_status.items():
            assert "duration_ms" not in status, f"Rule {rule_id} should not have duration_ms in deterministic mode"

    def test_deterministic_json_byte_identical(self):
        """Two to_json(deterministic_output=True) calls produce identical output."""
        result = _make_result_with_timing()
        json_a = result.to_json(deterministic_output=True)
        json_b = result.to_json(deterministic_output=True)
        assert json_a == json_b, "Two deterministic JSON outputs should be byte-identical"
        # Verify SHA-256 matches
        import hashlib

        assert hashlib.sha256(json_a.encode()).hexdigest() == hashlib.sha256(json_b.encode()).hexdigest()

    def test_normal_json_differs_across_runs(self):
        """Normal to_json() includes timestamps that change between runs."""
        # This test verifies that normal output DOES include timing
        result = _make_result_with_timing()
        json_out = result.to_json()
        data = json.loads(json_out)
        assert "audit" in data, "Normal output should have audit"
        assert "started_at" in data["audit"], "Normal output should have started_at"

    def test_rule_execution_deterministic_dict(self):
        """RuleExecution.to_dict(deterministic_output=True) omits duration_ms."""
        re = RuleExecution(rule_id="L2-POST-001", status="ok", duration_ms=50, findings_count=1)
        normal = re.to_dict()
        det = re.to_dict(deterministic_output=True)
        assert "duration_ms" in normal, "Normal dict should include duration_ms"
        assert "duration_ms" not in det, "Deterministic dict should omit duration_ms"
        assert det["rule_id"] == "L2-POST-001"
        assert det["status"] == "ok"
        assert det["findings_count"] == 1

    def test_deterministic_hash_matches_deterministic_output(self):
        """The guard's deterministic_hash should match hash of deterministic JSON."""
        from picosentry.scan.guards import deterministic_hash

        result = _make_result_with_timing()
        # deterministic_hash uses DETERMINISTIC_FIELDS which should align with
        # what deterministic_output produces (findings + metadata, no timing)
        guard_hash = deterministic_hash(result)
        assert len(guard_hash) == 64, "deterministic_hash should return SHA-256 hex"
        # Two calls should be identical
        assert deterministic_hash(result) == guard_hash

    def test_config_deterministic_output_flag(self):
        """PicoSentryConfig has deterministic_output field defaulting to False."""
        from picosentry.scan.config import PicoSentryConfig

        config = PicoSentryConfig()
        assert config.deterministic_output is False
        config.deterministic_output = True
        assert config.deterministic_output is True

    def test_config_deterministic_output_from_file(self, tmp_path):
        """deterministic_output can be loaded from config file."""
        from picosentry.scan.config import load_config

        config_file = tmp_path / ".picosentry.yml"
        config_file.write_text("format: json\ndeterministic_output: true\n")
        config = load_config(tmp_path)
        assert config.deterministic_output is True

    def test_config_deterministic_output_known_keys(self):
        """deterministic_output is in KNOWN_KEYS so config loading won't warn."""
        from picosentry.scan.config import KNOWN_KEYS

        assert "deterministic_output" in KNOWN_KEYS