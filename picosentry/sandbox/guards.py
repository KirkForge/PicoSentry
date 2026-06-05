"""
Deterministic guard stack — enforcement, verification, and fingerprinting.

PicoDome's core thesis: same command + same policy = same output, every time.

This module provides the guard stack that enforces and verifies that guarantee.
Core types (DeterminismViolation, DeterministicGuard base, deterministic_hash,
verify_determinism, diff_results) are imported from picosentry._core.guards.
PicoDome-specific logic (SandboxResult/AnalysisResult type dispatch,
validate_findings_deterministic, validate_result_sorted, validate_no_randomness)
remains here.

Architecture:
    ┌─────────────────────────────────────────┐
    │  Layer 4: CI Gate                       │
    │  --verify-determinism (CLI)             │
    │  Runs scan twice, asserts SHA-256 match │
    ├─────────────────────────────────────────┤
    │  Layer 3: Diff                          │
    │  picodome diff a.json b.json            │
    │  Compare two saved scans field-by-field │
    ├─────────────────────────────────────────┤
    │  Layer 2: Guard (runtime)               │
    │  Validates invariants after each scan:  │
    │  - No uuid4/random in findings          │
    │  - No timestamps in findings           │
    │  - Findings sorted by sort_key()        │
    │  - run_id is deterministic (empty)      │
    ├─────────────────────────────────────────┤
    │  Layer 1: Models (structural)           │
    │  Finding(frozen=True), sorted keys,    │
    │  no random IDs, no prose in output      │
    └─────────────────────────────────────────┘

Exit codes:
    0 = deterministic (verified)
    1 = different results (diff command)
    2 = file error
    4 = determinism violation (verify command)
"""

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

# Re-export for backward compatibility
__all__ = [
    "DeterminismViolation",
    "DeterministicGuard",
    "deterministic_hash",
    "diff_results",
    "validate_findings_deterministic",
    "validate_no_randomness",
    "validate_result_sorted",
    "verify_determinism",
]


class DeterministicGuard(_CoreGuard):
    """PicoDome-specific guard that validates SandboxResult and AnalysisResult.

    Extends the shared pico_core guard with PicoDome-specific type dispatch.
    Falls back to the core dict-based checks for shared invariants.
    """

    def check(self, result: SandboxResult | AnalysisResult) -> list[str]:
        """Validate determinism invariants. Returns list of violations (empty = pass)."""
        violations: list[str] = []

        if isinstance(result, SandboxResult):
            violations.extend(self._check_sandbox(result))
        elif isinstance(result, AnalysisResult):
            violations.extend(self._check_analysis(result))

        # Also run the shared dict-based checks
        result_dict = result.to_dict(deterministic=True)
        violations.extend(self.check_dict(result_dict))

        return violations

    def assert_deterministic(self, result: SandboxResult | AnalysisResult) -> None:
        """Assert result is deterministic. Raises DeterminismViolation if not."""
        violations = self.check(result)
        if violations:
            raise DeterminismViolation(violations)

    def _check_sandbox(self, result: SandboxResult) -> list[str]:
        """Check L3 SandboxResult for determinism violations."""
        violations: list[str] = []

        # 1. run_id must be empty (deterministic) or a valid UUID
        if result.run_id and _UUID_PATTERN.fullmatch(result.run_id):
            violations.append(f"run_id is a UUID (non-deterministic): {result.run_id}")

        # 2. timestamp must be empty (deterministic)
        if result.timestamp and _ISO_TIMESTAMP_PATTERN.search(result.timestamp):
            violations.append(f"timestamp is non-deterministic: {result.timestamp}")

        # 3. Events must not contain UUIDs in detail
        for event in result.events:
            if _UUID_PATTERN.search(event.detail):
                violations.append(f"event {event.rule_id} contains UUID in detail: {event.detail[:80]}")

        # 4. Verify to_dict produces sorted keys
        d = result.to_dict(deterministic=True)
        if list(d.keys()) != sorted(d.keys()):
            violations.append("SandboxResult.to_dict() keys are not sorted")

        return violations

    def _check_analysis(self, result: AnalysisResult) -> list[str]:
        """Check L4 AnalysisResult for determinism violations."""
        violations: list[str] = []

        # 1. Findings must not have UUID finding_ids
        for f in result.findings:
            if f.finding_id and _UUID_PATTERN.fullmatch(f.finding_id):
                violations.append(f"Finding {f.rule_id} has UUID finding_id: {f.finding_id}")

        # 2. No timestamps in finding data
        for f in result.findings:
            if hasattr(f, "timestamp") and f.timestamp:
                violations.append(f"Finding {f.rule_id} has timestamp: {f.timestamp}")

        # 3. Findings must be sorted (by rule_id, file, line, finding_id — the
        # canonical order for stable hash chain output). We don't use
        # Finding.sort_key() because the L4 sandbox Finding dataclass doesn't
        # define it; the L2 scanner's does.
        def _sort_tuple(f):
            return (f.rule_id, f.file, getattr(f, "line", 0), f.finding_id)
        sorted_findings = sorted(result.findings, key=_sort_tuple)
        if result.findings != sorted_findings:
            violations.append("findings not sorted by (rule_id, file, line, finding_id)")

        # 4. Verify to_dict produces sorted keys
        d = result.to_dict(deterministic=True)
        if list(d.keys()) != sorted(d.keys()):
            violations.append("AnalysisResult.to_dict() keys are not sorted")

        return violations


def validate_findings_deterministic(findings: list) -> list[str]:
    """Validate that a list of findings is deterministic.

    Checks for:
    - No UUID4 finding_ids
    - No timestamps in messages
    - No random values in evidence

    Returns list of violations (empty = pass).
    """
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


def validate_result_sorted(result_dict: dict) -> list[str]:
    """Validate that a result dict has sorted keys at all levels.

    Returns list of violations (empty = pass).
    """
    violations: list[str] = []

    def _check_sorted(d: dict, path: str = "") -> None:
        keys = list(d.keys())
        if keys != sorted(keys):
            violations.append(f"keys not sorted at {path or 'root'}: {keys}")
        for k, v in d.items():
            if isinstance(v, dict):
                _check_sorted(v, f"{path}.{k}" if path else k)

    _check_sorted(result_dict)
    return violations


def validate_no_randomness(result_dict: dict) -> list[str]:
    """Validate that a result dict contains no random values.

    Checks for UUIDs and timestamps anywhere in the dict.

    Returns list of violations (empty = pass).
    """
    violations: list[str] = []

    def _check_value(v, path: str = "") -> None:
        if isinstance(v, str):
            if _UUID_PATTERN.search(v):
                violations.append(f"UUID found at {path}: {v[:50]}")
            if _ISO_TIMESTAMP_PATTERN.search(v):
                violations.append(f"timestamp found at {path}: {v[:50]}")
        elif isinstance(v, dict):
            for k2, v2 in v.items():
                _check_value(v2, f"{path}.{k2}")
        elif isinstance(v, list):
            for i, item in enumerate(v):
                _check_value(item, f"{path}[{i}]")

    _check_value(result_dict)
    return violations


def deterministic_hash(result: SandboxResult | AnalysisResult) -> str:
    """SHA-256 hash of deterministic fields only.

    Uses the shared picosentry._core.guards.deterministic_hash on the serialized dict.
    """
    data = result.to_dict(deterministic=True)
    return _core_deterministic_hash(data)


def verify_determinism(
    target: list[str],
    policy=None,
    timeout: float | None = None,
    cwd: str | None = None,
) -> tuple:
    """Run sandbox twice and compare SHA-256 hashes.

    Returns (is_match, hash_a, hash_b).
    If is_match is True, the results are deterministic.
    If False, there's a bug in the sandbox.
    """
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
    """Compare two result JSON files.

    Delegates to picosentry._core.guards.diff_results with PicoDome-specific field names.
    """
    return _core_diff_results(
        path_a,
        path_b,
        verbose=verbose,
        id_field="run_id",
        findings_key="findings",
        exclude_fields=("run_id", "timestamp", "duration_ms"),
    )
