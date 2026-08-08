from __future__ import annotations

import hashlib
import json
from pathlib import Path

from picosentry._core.guards import (
    FORBIDDEN_IN_FINDINGS,
    DeterminismViolation,
)
from picosentry._core.guards import (
    DeterministicGuard as _CoreGuard,
)
from picosentry._core.guards import (
    diff_results as _core_diff_results,
)
from picosentry._core.guards import (
    verify_determinism as _core_verify_determinism,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from picosentry.scan.models import ScanResult


__all__ = [
    "DETERMINISTIC_FIELDS",
    "DeterminismViolation",
    "DeterministicGuard",
    "deterministic_hash",
    "diff_scans",
    "fingerprint_scan",
    "verify_determinism",
]


DETERMINISTIC_FIELDS = frozenset(
    {
        "scan_id",
        "engine_version",
        "corpus_version",
        "target",
        "findings",
        "stats",
    }
)


class DeterministicGuard(_CoreGuard):  # rationale: extends pico_core guard with PicoSentry-specific scan checks
    def assert_deterministic(self, result: ScanResult) -> None:
        violations = self.check(result)
        if violations:
            raise DeterminismViolation(violations)

    def check(self, result: ScanResult) -> list[str]:
        violations: list[str] = []

        sorted_findings = sorted(result.findings, key=lambda f: f.sort_key())
        if result.findings != sorted_findings:
            violations.append("findings not sorted by (rule_id, package, file, line)")

        fingerprints = [f.fingerprint() for f in result.findings]
        if len(fingerprints) != len(set(fingerprints)):
            violations.append("duplicate findings detected (same rule_id, package, file)")

        expected_id = hashlib.sha256(
            f"{result.target}:{result.corpus_version}:{result.engine_version}".encode()
        ).hexdigest()[:16]
        if result.scan_id != expected_id:
            violations.append(f"scan_id mismatch: expected {expected_id}, got {result.scan_id}")

        violations.extend(
            f"forbidden pattern '{pattern}' in finding {f.rule_id} {f.package}"
            for f in result.findings
            for pattern in FORBIDDEN_IN_FINDINGS
            if pattern in f.evidence or pattern in f.message or pattern in f.remediation
        )

        for f in result.findings:
            if not f.rule_id:
                violations.append(f"finding missing rule_id: {f}")
            if not f.package:
                violations.append(f"finding missing package: {f}")

        if result.stats.findings_by_severity or result.stats.findings_by_rule:
            by_sev: dict[str, int] = {}
            by_rule: dict[str, int] = {}
            for f in result.findings:
                by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
                by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
            expected_sev = dict(sorted(by_sev.items()))
            expected_rule = dict(sorted(by_rule.items()))
            if result.stats.findings_by_severity != expected_sev:
                violations.append(
                    f"findings_by_severity mismatch: stats={result.stats.findings_by_severity} actual={expected_sev}"
                )
            if result.stats.findings_by_rule != expected_rule:
                violations.append(
                    f"findings_by_rule mismatch: stats={result.stats.findings_by_rule} actual={expected_rule}"
                )

        result_dict = json.loads(result.to_json(deterministic_output=True))
        violations.extend(self.check_dict(result_dict))

        return violations


# rationale: include-list hashing, only hashes known-deterministic fields
def deterministic_hash(result: ScanResult) -> str:
    data = json.loads(result.to_json(deterministic_output=True))
    det: dict = {k: v for k, v in data.items() if k in DETERMINISTIC_FIELDS}

    if "stats" in det and isinstance(det["stats"], dict):
        det["stats"] = {k: v for k, v in det["stats"].items() if k not in ("duration_ms", "rule_timings_ms")}
    return hashlib.sha256(json.dumps(det, sort_keys=True).encode()).hexdigest()


def fingerprint_scan(result: ScanResult) -> str:
    return deterministic_hash(result)[:16]


def verify_determinism(
    result_a: ScanResult,
    result_b: ScanResult,
) -> tuple[bool, str, str]:
    hash_a = deterministic_hash(result_a)
    hash_b = deterministic_hash(result_b)
    return _core_verify_determinism(hash_a, hash_b)


def diff_scans(
    path_a: Path,
    path_b: Path,
    verbose: bool = False,
) -> tuple[int, str]:
    _diff_exclude = (
        "run_id",
        "timestamp",
        "duration_ms",
        "scan_id",
        "started_at",
        "completed_at",
        "audit",
        "rule_status",
        "package_intel",
        "behavioral_evidence",
    )
    return _core_diff_results(
        path_a,
        path_b,
        verbose=verbose,
        id_field="scan_id",
        findings_key="findings",
        exclude_fields=_diff_exclude,
    )
