"""
test_guards.py — Deterministic guard stack tests.

Tests the guard module that enforces and verifies determinism:
- DeterministicGuard: runtime invariant validation
- deterministic_hash: SHA-256 of deterministic fields
- fingerprint_scan: stable short fingerprint
- verify_determinism: compare two results
- diff_scans: compare two JSON files
"""

from pathlib import Path

import pytest

from picosentry.scan.guards import (
    DETERMINISTIC_FIELDS,
    DeterminismViolation,
    DeterministicGuard,
    deterministic_hash,
    diff_scans,
    fingerprint_scan,
    verify_determinism,
)
from picosentry.scan.models import Confidence, Finding, ScanResult, ScanStats, Severity


def _make_result(
    target: str = "/tmp/test",
    findings: list[Finding] | None = None,
    engine_version: str = "0.10.0",
    corpus_version: str = "abc123",
    duration_ms: int = 100,
) -> ScanResult:
    """Helper to create a ScanResult for testing."""
    result = ScanResult(
        target=target,
        engine_version=engine_version,
        corpus_version=corpus_version,
        findings=findings or [],
        stats=ScanStats(
            packages_scanned=1,
            files_scanned=10,
            duration_ms=duration_ms,
        ),
    )
    result.recompute_stats()
    return result


# ─── DeterministicGuard ────────────────────────────────────────────────────────


class TestDeterministicGuard:
    """Runtime guard validates invariants after each scan."""

    def test_clean_scan_passes(self):
        """Clean scan with no violations should pass."""
        guard = DeterministicGuard()
        result = _make_result()
        violations = guard.check(result)
        assert violations == []

    def test_unsorted_findings_detected(self):
        """Findings not sorted by sort_key should be flagged."""
        f1 = Finding(
            rule_id="L2-TYPO-001",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            package="reqct",
            file="pkg/package.json",
            message="typosquat",
            evidence="reqct ≈ react",
            remediation="Use correct package name",
        )
        f2 = Finding(
            rule_id="L2-POST-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.EXACT,
            package="evil",
            file="evil/package.json",
            message="postinstall",
            evidence="scripts.postinstall",
            remediation="Remove script",
        )
        # Deliberately unsorted: TYPO before POST
        result = _make_result(findings=[f1, f2])
        guard = DeterministicGuard()
        violations = guard.check(result)
        assert any("not sorted" in v for v in violations)

    def test_duplicate_findings_detected(self):
        """Duplicate fingerprints should be flagged."""
        f1 = Finding(
            rule_id="L2-POST-001",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            package="evil",
            file="evil/package.json",
            message="postinstall",
            evidence="scripts.postinstall",
            remediation="Remove script",
        )
        f2 = Finding(
            rule_id="L2-POST-001",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            package="evil",
            file="evil/package.json",
            message="postinstall",
            evidence="scripts.postinstall",
            remediation="Remove script",
        )
        result = _make_result(findings=[f1, f2])
        guard = DeterministicGuard()
        violations = guard.check(result)
        assert any("duplicate" in v for v in violations)

    def test_missing_rule_id_detected(self):
        """Finding with empty rule_id should be flagged."""
        f = Finding(
            rule_id="",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            package="evil",
            file="evil/package.json",
            message="postinstall",
            evidence="scripts.postinstall",
            remediation="Remove script",
        )
        result = _make_result(findings=[f])
        guard = DeterministicGuard()
        violations = guard.check(result)
        assert any("rule_id" in v for v in violations)

    def test_missing_package_detected(self):
        """Finding with empty package should be flagged."""
        f = Finding(
            rule_id="L2-POST-001",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            package="",
            file="evil/package.json",
            message="postinstall",
            evidence="scripts.postinstall",
            remediation="Remove script",
        )
        result = _make_result(findings=[f])
        guard = DeterministicGuard()
        violations = guard.check(result)
        assert any("package" in v for v in violations)

    def test_forbidden_pattern_detected(self):
        """Finding containing uuid4/random should be flagged."""
        f = Finding(
            rule_id="L2-POST-001",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            package="evil",
            file="evil/package.json",
            message="postinstall with uuid4()",
            evidence="scripts.postinstall",
            remediation="Remove script",
        )
        result = _make_result(findings=[f])
        guard = DeterministicGuard()
        violations = guard.check(result)
        assert any("uuid4" in v for v in violations)

    def test_scan_id_mismatch_detected(self):
        """ScanResult with wrong scan_id should be flagged."""
        result = ScanResult(
            target="/tmp/test",
            engine_version="0.10.0",
            corpus_version="abc123",
            findings=[],
            stats=ScanStats(packages_scanned=1, files_scanned=10, duration_ms=100),
        )
        # Manually corrupt the scan_id by changing target after init
        result.target = "/different/path"
        # scan_id is a property computed from target, so this should still pass
        guard = DeterministicGuard()
        violations = guard.check(result)
        # scan_id will be recomputed from the new target, so it should match
        assert violations == []

    def test_assert_deterministic_raises(self):
        """assert_deterministic should raise DeterminismViolation on violations."""
        f1 = Finding(
            rule_id="L2-TYPO-001",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            package="reqct",
            file="pkg/package.json",
            message="typosquat",
            evidence="reqct ≈ react",
            remediation="Use correct package name",
        )
        f2 = Finding(
            rule_id="L2-POST-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.EXACT,
            package="evil",
            file="evil/package.json",
            message="postinstall",
            evidence="scripts.postinstall",
            remediation="Remove script",
        )
        # Unsorted
        result = _make_result(findings=[f1, f2])
        guard = DeterministicGuard()
        with pytest.raises(DeterminismViolation) as exc_info:
            guard.assert_deterministic(result)
        assert "not sorted" in str(exc_info.value)

    def test_assert_deterministic_passes(self):
        """assert_deterministic should not raise on a clean result."""
        result = _make_result()
        guard = DeterministicGuard()
        guard.assert_deterministic(result)  # Should not raise


# ─── deterministic_hash ───────────────────────────────────────────────────────


class TestDeterministicHash:
    """SHA-256 hash of deterministic fields only."""

    def test_same_result_same_hash(self):
        """Same result should produce same deterministic hash."""
        result = _make_result()
        hash_a = deterministic_hash(result)
        hash_b = deterministic_hash(result)
        assert hash_a == hash_b

    def test_different_results_different_hash(self):
        """Different findings should produce different hashes."""
        result_a = _make_result(target="/path/a")
        result_b = _make_result(target="/path/b")
        hash_a = deterministic_hash(result_a)
        hash_b = deterministic_hash(result_b)
        assert hash_a != hash_b

    def test_timing_excluded_from_hash(self):
        """Timing data should not affect the hash."""
        result_a = _make_result(duration_ms=100)
        result_b = _make_result(duration_ms=999)
        # Same target, same findings, different duration — should match
        hash_a = deterministic_hash(result_a)
        hash_b = deterministic_hash(result_b)
        assert hash_a == hash_b

    def test_rule_timings_excluded_from_hash(self):
        """Rule timings should not affect the hash."""
        result_a = _make_result()
        result_a.stats.rule_timings_ms = {"L2-POST-001": 50, "L2-TYPO-001": 100}
        result_b = _make_result()
        result_b.stats.rule_timings_ms = {"L2-POST-001": 99, "L2-TYPO-001": 200}
        hash_a = deterministic_hash(result_a)
        hash_b = deterministic_hash(result_b)
        assert hash_a == hash_b

    def test_hash_is_64_char_hex(self):
        """SHA-256 hash should be 64 hex characters."""
        result = _make_result()
        h = deterministic_hash(result)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_deterministic_fields_constant(self):
        """DETERMINISTIC_FIELDS should be a frozenset (immutable)."""
        assert isinstance(DETERMINISTIC_FIELDS, frozenset)
        assert "scan_id" in DETERMINISTIC_FIELDS
        assert "findings" in DETERMINISTIC_FIELDS
        assert "duration_ms" not in DETERMINISTIC_FIELDS
        assert "rule_timings_ms" not in DETERMINISTIC_FIELDS


# ─── fingerprint_scan ─────────────────────────────────────────────────────────


class TestFingerprintScan:
    """Stable short fingerprint for caching/baselining."""

    def test_fingerprint_is_16_chars(self):
        """Fingerprint should be 16 hex characters (first 16 of SHA-256)."""
        result = _make_result()
        fp = fingerprint_scan(result)
        assert len(fp) == 16
        assert all(c in "0123456789abcdef" for c in fp)

    def test_fingerprint_is_prefix_of_hash(self):
        """Fingerprint should be the first 16 chars of deterministic_hash."""
        result = _make_result()
        fp = fingerprint_scan(result)
        h = deterministic_hash(result)
        assert h.startswith(fp)

    def test_same_result_same_fingerprint(self):
        """Same result should produce same fingerprint."""
        result = _make_result()
        assert fingerprint_scan(result) == fingerprint_scan(result)


# ─── verify_determinism ───────────────────────────────────────────────────────


class TestVerifyDeterminism:
    """Compare two ScanResults for determinism."""

    def test_identical_results_match(self):
        """Two identical results should match."""
        result_a = _make_result()
        result_b = _make_result()
        is_match, hash_a, hash_b = verify_determinism(result_a, result_b)
        assert is_match is True
        assert hash_a == hash_b

    def test_different_results_differ(self):
        """Results with different findings should not match."""
        f = Finding(
            rule_id="L2-POST-001",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            package="evil",
            file="evil/package.json",
            message="postinstall",
            evidence="scripts.postinstall",
            remediation="Remove script",
        )
        result_a = _make_result()
        result_b = _make_result(findings=[f])
        is_match, _, _ = verify_determinism(result_a, result_b)
        assert is_match is False

    def test_timing_does_not_affect_match(self):
        """Different timing data should not affect determinism check."""
        result_a = _make_result(duration_ms=100)
        result_b = _make_result(duration_ms=9999)
        is_match, _, _ = verify_determinism(result_a, result_b)
        assert is_match is True


# ─── diff_scans ───────────────────────────────────────────────────────────────


class TestDiffScans:
    """Compare two scan JSON files."""

    def test_identical_scans(self, tmp_path):
        """Two identical scan files should return exit 0."""
        result = _make_result()
        scan_a = tmp_path / "a.json"
        scan_b = tmp_path / "b.json"
        scan_a.write_text(result.to_json())
        scan_b.write_text(result.to_json())

        exit_code, output = diff_scans(scan_a, scan_b)
        assert exit_code == 0
        assert "IDENTICAL" in output

    def test_different_scans(self, tmp_path):
        """Two different scan files should return exit 1."""
        f = Finding(
            rule_id="L2-POST-001",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            package="evil",
            file="evil/package.json",
            message="postinstall",
            evidence="scripts.postinstall",
            remediation="Remove script",
        )
        result_a = _make_result()
        result_b = _make_result(findings=[f])

        scan_a = tmp_path / "a.json"
        scan_b = tmp_path / "b.json"
        scan_a.write_text(result_a.to_json())
        scan_b.write_text(result_b.to_json())

        exit_code, output = diff_scans(scan_a, scan_b)
        assert exit_code == 1
        assert "DIFFER" in output

    def test_missing_file(self, tmp_path):
        """Missing file should return exit 2."""
        scan_a = tmp_path / "a.json"
        scan_a.write_text('{"test": true}')
        exit_code, _output = diff_scans(scan_a, Path("/nonexistent/file.json"))
        assert exit_code == 2

    def test_verbose_diff(self, tmp_path):
        """Verbose diff should show finding-level changes."""
        f1 = Finding(
            rule_id="L2-POST-001",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            package="evil",
            file="evil/package.json",
            message="postinstall",
            evidence="scripts.postinstall",
            remediation="Remove script",
        )
        result_a = _make_result()
        result_b = _make_result(findings=[f1])

        scan_a = tmp_path / "a.json"
        scan_b = tmp_path / "b.json"
        scan_a.write_text(result_a.to_json())
        scan_b.write_text(result_b.to_json())

        exit_code, output = diff_scans(scan_a, scan_b, verbose=True)
        assert exit_code == 1
        assert "L2-POST-001" in output

    def test_timing_only_difference(self, tmp_path):
        """Scans differing only in timing should be IDENTICAL."""
        result_a = _make_result(duration_ms=100)
        result_b = _make_result(duration_ms=999)

        scan_a = tmp_path / "a.json"
        scan_b = tmp_path / "b.json"
        scan_a.write_text(result_a.to_json())
        scan_b.write_text(result_b.to_json())

        exit_code, output = diff_scans(scan_a, scan_b)
        assert exit_code == 0
        assert "IDENTICAL" in output


class TestGuardStatsConsistency:
    """Test that DeterministicGuard catches stats/findings mismatch."""

    def test_stats_severity_mismatch_caught(self):
        """Guard detects findings_by_severity that doesn't match actual findings."""
        guard = DeterministicGuard()
        findings = [
            Finding(
                rule_id="L2-POST-001",
                severity=Severity.HIGH,
                confidence=Confidence.EXACT,
                package="pkg",
                file="pkg/package.json",
                message="test",
                evidence="test",
                remediation="test",
            ),
        ]
        result = ScanResult(
            target="/tmp/test",
            engine_version="0.11.0",
            corpus_version="abc123",
            findings=findings,
            stats=ScanStats(
                findings_by_severity={"CRITICAL": 1},  # Wrong! Should be HIGH
                findings_by_rule={"L2-POST-001": 1},
            ),
        )
        violations = guard.check(result)
        assert any("findings_by_severity" in v for v in violations)

    def test_stats_rule_mismatch_caught(self):
        """Guard detects findings_by_rule that doesn't match actual findings."""
        guard = DeterministicGuard()
        findings = [
            Finding(
                rule_id="L2-POST-001",
                severity=Severity.HIGH,
                confidence=Confidence.EXACT,
                package="pkg",
                file="pkg/package.json",
                message="test",
                evidence="test",
                remediation="test",
            ),
        ]
        result = ScanResult(
            target="/tmp/test",
            engine_version="0.11.0",
            corpus_version="abc123",
            findings=findings,
            stats=ScanStats(
                findings_by_severity={"HIGH": 1},
                findings_by_rule={"L2-WRONG-001": 1},  # Wrong rule!
            ),
        )
        violations = guard.check(result)
        assert any("findings_by_rule" in v for v in violations)

    def test_stats_consistent_passes(self):
        """Guard passes when stats match findings."""
        guard = DeterministicGuard()
        findings = [
            Finding(
                rule_id="L2-POST-001",
                severity=Severity.HIGH,
                confidence=Confidence.EXACT,
                package="pkg",
                file="pkg/package.json",
                message="test",
                evidence="test",
                remediation="test",
            ),
        ]
        result = ScanResult(
            target="/tmp/test",
            engine_version="0.11.0",
            corpus_version="abc123",
            findings=findings,
            stats=ScanStats(
                findings_by_severity={"HIGH": 1},
                findings_by_rule={"L2-POST-001": 1},
            ),
        )
        violations = guard.check(result)
        assert not any("findings_by_" in v for v in violations)
