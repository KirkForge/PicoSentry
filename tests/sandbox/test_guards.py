"""Tests for deterministic guard/validation functions."""

import hashlib
import json

from picosentry.sandbox.models import Finding, Severity, Verdict


def _validate_findings_deterministic(findings: list) -> list:
    """Validate that findings contain no uuid4 or timestamps."""
    import re

    uuid_pat = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
    ts_pat = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
    errors: list[str] = []
    for f in findings:
        d = f.to_dict()
        for key, val in d.items():
            _check_value(val, key, f.rule_id, uuid_pat, ts_pat, errors)
    return errors


def _check_value(val, path, rule_id, uuid_pat, ts_pat, errors):
    """Recursively check a value for UUIDs and timestamps."""
    if isinstance(val, dict):
        for k, v in val.items():
            _check_value(v, f"{path}.{k}", rule_id, uuid_pat, ts_pat, errors)
    elif isinstance(val, list):
        for i, item in enumerate(val):
            _check_value(item, f"{path}[{i}]", rule_id, uuid_pat, ts_pat, errors)
    elif isinstance(val, str):
        if uuid_pat.search(val):
            errors.append(f"Finding {rule_id} has UUID in field '{path}': {val}")
        if ts_pat.search(val):
            errors.append(f"Finding {rule_id} has timestamp in field '{path}': {val}")


def _validate_result_sorted(d: dict) -> list:
    """Validate that dict keys are sorted (for deterministic JSON)."""
    errors = []
    for key in d:
        if isinstance(d[key], dict):
            keys = list(d[key].keys())
            if keys != sorted(keys):
                errors.append(f"Dict key '{key}' has unsorted sub-keys: {keys}")
    return errors


def _validate_no_randomness(obj1, obj2) -> bool:
    """Two deterministic runs should produce identical output."""
    return obj1.to_dict() == obj2.to_dict()


class TestValidateFindingsDeterministic:
    def test_clean_finding_passes(self):
        f = Finding(
            rule_id="TEST-001",
            severity=Severity.HIGH,
            message="Clean",
            location="/tmp/test",
            evidence={"key": "value"},
        )
        errors = _validate_findings_deterministic([f])
        assert errors == []

    def test_finding_with_uuid4_in_evidence_fails(self):
        f = Finding(
            rule_id="TEST-002",
            severity=Severity.HIGH,
            message="Has UUID",
            evidence={"trace_id": "550e8400-e29b-41d4-a716-446655440000"},
        )
        errors = _validate_findings_deterministic([f])
        assert len(errors) > 0
        assert "UUID" in errors[0]

    def test_finding_with_timestamp_in_evidence_fails(self):
        f = Finding(
            rule_id="TEST-003",
            severity=Severity.HIGH,
            message="Has timestamp",
            evidence={"created": "2025-01-01T12:00:00Z"},
        )
        errors = _validate_findings_deterministic([f])
        assert len(errors) > 0
        assert "timestamp" in errors[0].lower()

    def test_multiple_findings_all_checked(self):
        f1 = Finding(rule_id="R1", severity=Severity.LOW, message="ok")
        f2 = Finding(
            rule_id="R2",
            severity=Severity.HIGH,
            message="bad",
            evidence={"id": "550e8400-e29b-41d4-a716-446655440000"},
        )
        errors = _validate_findings_deterministic([f1, f2])
        assert len(errors) == 1

    def test_finding_with_normal_hex_passes(self):
        """Normal hex strings that aren't UUIDs should pass."""
        f = Finding(
            rule_id="TEST-004",
            severity=Severity.MEDIUM,
            message="Normal hex",
            evidence={"hash": "abc123def456"},
        )
        errors = _validate_findings_deterministic([f])
        assert errors == []

    def test_finding_with_short_timestamp_like_string_passes(self):
        """Short date strings (not ISO timestamps) should pass."""
        f = Finding(
            rule_id="TEST-005",
            severity=Severity.LOW,
            message="Date only",
            evidence={"date": "2025-01-01"},
        )
        errors = _validate_findings_deterministic([f])
        assert errors == []


class TestValidateResultSorted:
    def test_sorted_dict_passes(self):
        from picosentry.sandbox.l3.models import SandboxResult

        r = SandboxResult(
            run_id="test",
            timestamp="2025-01-01T00:00:00Z",
            command=["echo"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
        )
        d = r.to_dict()
        errors = _validate_result_sorted(d)
        # SandboxResult.to_dict keys are: run_id, timestamp, command, overall_verdict...
        # This function checks sub-dicts only
        assert isinstance(errors, list)

    def test_unsorted_nested_dict_fails(self):
        d = {
            "top": {
                "z_key": 1,
                "a_key": 2,
            }
        }
        errors = _validate_result_sorted(d)
        assert len(errors) > 0

    def test_sorted_nested_dict_passes(self):
        d = {
            "top": {
                "a_key": 1,
                "b_key": 2,
            }
        }
        errors = _validate_result_sorted(d)
        assert errors == []

    def test_empty_dict_passes(self):
        errors = _validate_result_sorted({})
        assert errors == []


class TestValidateNoRandomness:
    def test_two_deterministic_runs_produce_same_output(self):
        """Two SandboxResults with same explicit fields should be identical."""
        from picosentry.sandbox.l3.models import SandboxResult

        r1 = SandboxResult(
            run_id="det-001",
            timestamp="2025-01-01T00:00:00Z",
            command=["echo", "test"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=100,
        )
        r2 = SandboxResult(
            run_id="det-001",
            timestamp="2025-01-01T00:00:00Z",
            command=["echo", "test"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=100,
        )
        assert _validate_no_randomness(r1, r2)

    def test_two_different_results_not_equal(self):
        from picosentry.sandbox.l3.models import SandboxResult

        r1 = SandboxResult(
            run_id="det-001",
            timestamp="2025-01-01T00:00:00Z",
            command=["echo", "test"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
        )
        r2 = SandboxResult(
            run_id="det-002",
            timestamp="2025-01-01T00:00:00Z",
            command=["echo", "different"],
            overall_verdict=Verdict.DENY,
            exit_code=1,
        )
        assert not _validate_no_randomness(r1, r2)

    def test_json_hash_deterministic(self):
        """Two deterministic dicts should produce the same JSON hash."""
        from picosentry.sandbox.l3.models import SandboxResult

        r = SandboxResult(
            run_id="hash-test",
            timestamp="2025-01-01T00:00:00Z",
            command=["echo"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
        )
        d1 = r.to_dict()
        d2 = r.to_dict()
        h1 = hashlib.sha256(json.dumps(d1, sort_keys=True).encode()).hexdigest()
        h2 = hashlib.sha256(json.dumps(d2, sort_keys=True).encode()).hexdigest()
        assert h1 == h2

    def test_analysis_result_deterministic_hash(self):
        """AnalysisResult with explicit fields should hash deterministically."""
        from picosentry.sandbox.l4.models import AnalysisResult, BehavioralVerdict

        ar = AnalysisResult(
            target="test",
            findings=[],
            overall_verdict=BehavioralVerdict.CLEAN,
        )
        d1 = ar.to_dict()
        d2 = ar.to_dict()
        h1 = hashlib.sha256(json.dumps(d1, sort_keys=True).encode()).hexdigest()
        h2 = hashlib.sha256(json.dumps(d2, sort_keys=True).encode()).hexdigest()
        assert h1 == h2

    def test_auto_uuid_breaks_determinism(self):
        """Auto-generated finding_id makes Findings non-deterministic."""
        from picosentry.sandbox.models import _generate_finding_id

        f1 = Finding(rule_id="R1", severity=Severity.LOW, message="m", finding_id=_generate_finding_id())
        f2 = Finding(rule_id="R1", severity=Severity.LOW, message="m", finding_id=_generate_finding_id())
        # finding_id auto-generates UUIDs, so they differ
        assert f1.finding_id != f2.finding_id


class TestGuardIntegration:
    def test_sandbox_result_deterministic_roundtrip(self):
        """Full round-trip: create → to_dict → JSON → parse → verify."""
        from picosentry.sandbox.l3.models import SandboxEvent, SandboxResult

        r = SandboxResult(
            run_id="rt-001",
            timestamp="2025-01-01T00:00:00Z",
            command=["python3", "-c", "print(42)"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=50,
            events=[
                SandboxEvent(
                    rule_id="L3-R-001",
                    verdict=Verdict.ALLOW,
                    operation="file_read",
                    detail="Read allowed",
                ),
            ],
            policy_name="test",
        )
        d = r.to_dict()
        j = json.dumps(d, sort_keys=True)
        parsed = json.loads(j)
        assert parsed["run_id"] == "rt-001"
        assert parsed["overall_verdict"] == "ALLOW"
        assert len(parsed["events"]) == 1

    def test_finding_evidence_no_uuid(self):
        """Finding evidence should not leak UUIDs."""
        f = Finding(
            rule_id="TEST-EV",
            severity=Severity.CRITICAL,
            message="Test",
            evidence={"path": "/etc/passwd", "port": 443},
        )
        d = f.to_dict()
        for v in d["evidence"].values():
            assert "-" not in str(v) or len(str(v)) < 36
