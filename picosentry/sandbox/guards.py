from __future__ import annotations

from pathlib import Path

from picosentry._core.guards import (
    ISO_TIMESTAMP_PATTERN as _ISO_TIMESTAMP_PATTERN,
)
from picosentry._core.guards import (
    UUID_PATTERN as _UUID_PATTERN,
)
from picosentry._core.guards import (
    DeterminismViolation,
)
from picosentry._core.guards import (
    DeterministicGuard as _CoreGuard,
)
from picosentry._core.guards import (
    deterministic_hash as _core_deterministic_hash,
)
from picosentry._core.guards import (
    diff_results as _core_diff_results,
)
from picosentry._core.guards import (
    verify_determinism as _core_verify_determinism,
)
from picosentry.sandbox.l3.models import SandboxResult
from picosentry.sandbox.l4.models import AnalysisResult


__all__ = [
    "DeterminismViolation",
    "DeterministicGuard",
    "deterministic_hash",
    "diff_results",
    "validate_findings_deterministic",
    "verify_determinism",
]


class DeterministicGuard(_CoreGuard):
    def check(self, result: SandboxResult | AnalysisResult) -> list[str]:
        violations: list[str] = []

        if isinstance(result, SandboxResult):
            violations.extend(self._check_sandbox(result))
        elif isinstance(result, AnalysisResult):
            violations.extend(self._check_analysis(result))

        result_dict = result.to_dict(deterministic=True)
        violations.extend(self.check_dict(result_dict))

        return violations

    def assert_deterministic(self, result: SandboxResult | AnalysisResult) -> None:
        violations = self.check(result)
        if violations:
            raise DeterminismViolation(violations)

    def _check_sandbox(self, result: SandboxResult) -> list[str]:
        violations: list[str] = []

        if result.run_id and _UUID_PATTERN.fullmatch(result.run_id):
            violations.append(f"run_id is a UUID (non-deterministic): {result.run_id}")

        if result.timestamp and _ISO_TIMESTAMP_PATTERN.search(result.timestamp):
            violations.append(f"timestamp is non-deterministic: {result.timestamp}")

        violations.extend(
            f"event {event.rule_id} contains UUID in detail: {event.detail[:80]}"
            for event in result.events
            if _UUID_PATTERN.search(event.detail)
        )

        d = result.to_dict(deterministic=True)
        if list(d.keys()) != sorted(d.keys()):
            violations.append("SandboxResult.to_dict() keys are not sorted")

        return violations

    def _check_analysis(self, result: AnalysisResult) -> list[str]:
        violations: list[str] = []

        violations.extend(
            f"Finding {f.rule_id} has UUID finding_id: {f.finding_id}"
            for f in result.findings
            if f.finding_id and _UUID_PATTERN.fullmatch(f.finding_id)
        )

        violations.extend(
            f"Finding {f.rule_id} has timestamp: {f.timestamp}"
            for f in result.findings
            if hasattr(f, "timestamp") and f.timestamp
        )

        def _sort_tuple(f):
            return (f.rule_id, f.file, getattr(f, "line", 0), f.finding_id)

        sorted_findings = sorted(result.findings, key=_sort_tuple)
        if result.findings != sorted_findings:
            violations.append("findings not sorted by (rule_id, file, line, finding_id)")

        d = result.to_dict(deterministic=True)
        if list(d.keys()) != sorted(d.keys()):
            violations.append("AnalysisResult.to_dict() keys are not sorted")

        return violations


def validate_findings_deterministic(findings: list) -> list[str]:
    violations: list[str] = []

    for f in findings:
        if f.finding_id and _UUID_PATTERN.fullmatch(f.finding_id):
            violations.append(f"finding {f.rule_id} has UUID finding_id: {f.finding_id}")
        if _ISO_TIMESTAMP_PATTERN.search(f.message):
            violations.append(f"finding {f.rule_id} has timestamp in message")
        evidence_str = str(f.evidence)
        if _UUID_PATTERN.search(evidence_str):
            violations.append(f"finding {f.rule_id} has UUID in evidence")

    return violations


def deterministic_hash(result: SandboxResult | AnalysisResult) -> str:
    data = result.to_dict(deterministic=True)
    return _core_deterministic_hash(data)


def verify_determinism(
    target: list[str],
    policy=None,
    timeout: float | None = None,
    cwd: str | None = None,
) -> tuple:
    from picosentry.sandbox.l3.engine import sandbox_run

    result_a = sandbox_run(target, policy=policy, timeout=timeout, cwd=cwd, deterministic=True)
    result_b = sandbox_run(target, policy=policy, timeout=timeout, cwd=cwd, deterministic=True)

    hash_a = deterministic_hash(result_a)
    hash_b = deterministic_hash(result_b)

    return _core_verify_determinism(hash_a, hash_b)


def diff_results(
    path_a: Path,
    path_b: Path,
    verbose: bool = False,
) -> tuple:
    return _core_diff_results(
        path_a,
        path_b,
        verbose=verbose,
        id_field="run_id",
        findings_key="findings",
        exclude_fields=("run_id", "timestamp", "duration_ms"),
    )
