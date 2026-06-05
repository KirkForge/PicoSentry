"""
Deterministic guard stack — enforcement, verification, and fingerprinting.

PicoSentry's core thesis: same inputs + same corpus = same output, every time.

Core types (DeterminismViolation, DeterministicGuard base, verify_determinism)
are imported from picosentry._core.guards. PicoSentry-specific logic (ScanResult
type dispatch, fingerprint_scan, DETERMINISTIC_FIELDS, diff_scans) remains
here because PicoSentry uses an include-list approach (only hash known
deterministic fields) rather than the exclude-list approach used by PicoDome.

Architecture:
    ┌─────────────────────────────────────────┐
    │  Layer 4: CI Gate                       │
    │  --verify-determinism (CLI)             │
    │  Runs scan twice, asserts SHA-256 match │
    ├─────────────────────────────────────────┤
    │  Layer 3: Diff                          │
    │  picosentry diff a.json b.json          │
    │  Compare two saved scans field-by-field │
    ├─────────────────────────────────────────┤
    │  Layer 2: Guard (runtime)               │
    │  Validates invariants after each scan:  │
    │  - No uuid4/random in findings          │
    │  - No timestamps in findings           │
    │  - Findings sorted by sort_key()        │
    │  - scan_id is deterministic SHA-256     │
    ├─────────────────────────────────────────┤
    │  Layer 1: Models (structural)           │
    │  Finding(frozen=True), sorted keys,    │
    │  no random IDs, no prose in output     │
    └─────────────────────────────────────────┘

Exit codes:
    0 = deterministic (verified)
    1 = different findings (diff command)
    2 = file error
    4 = determinism violation (verify command)
"""

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
    verify_determinism as _core_verify_determinism,
)
from picosentry.scan.models import ScanResult

# Re-export for backward compatibility
__all__ = [
    "DETERMINISTIC_FIELDS",
    "DeterminismViolation",
    "DeterministicGuard",
    "deterministic_hash",
    "diff_scans",
    "fingerprint_scan",
    "verify_determinism",
]

# Fields included in deterministic comparison.
# PicoSentry uses an include-list approach: only hash these known-deterministic fields,
# excluding audit, rule_status, scan_completeness, etc. which contain timing data.
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
    """PicoSentry-specific guard that validates ScanResult objects.

    Extends the shared pico_core guard with PicoSentry-specific checks
    (scan_id determinism, finding sort order, forbidden patterns).
    """

    def assert_deterministic(self, result: ScanResult) -> None:
        """Assert that a scan result is deterministic. Raises DeterminismViolation if not."""
        violations = self.check(result)
        if violations:
            raise DeterminismViolation(violations)

    def check(self, result: ScanResult) -> list[str]:
        """Validate determinism invariants. Returns list of violations (empty = pass)."""
        violations: list[str] = []

        # 1. Findings must be sorted by sort_key
        sorted_findings = sorted(result.findings, key=lambda f: f.sort_key())
        if result.findings != sorted_findings:
            violations.append("findings not sorted by (rule_id, package, file, line)")

        # 2. No duplicate findings
        fingerprints = [f.fingerprint() for f in result.findings]
        if len(fingerprints) != len(set(fingerprints)):
            violations.append("duplicate findings detected (same rule_id, package, file)")

        # 3. scan_id must be deterministic (not random)
        expected_id = hashlib.sha256(
            f"{result.target}:{result.corpus_version}:{result.engine_version}".encode()
        ).hexdigest()[:16]
        if result.scan_id != expected_id:
            violations.append(f"scan_id mismatch: expected {expected_id}, got {result.scan_id}")

        # 4. No forbidden patterns in finding fields
        for f in result.findings:
            for pattern in FORBIDDEN_IN_FINDINGS:
                if pattern in f.evidence or pattern in f.message or pattern in f.remediation:
                    violations.append(f"forbidden pattern '{pattern}' in finding {f.rule_id} {f.package}")

        # 5. All findings must have required fields
        for f in result.findings:
            if not f.rule_id:
                violations.append(f"finding missing rule_id: {f}")
            if not f.package:
                violations.append(f"finding missing package: {f}")

        # 6. Stats must match actual findings
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

        # Also run shared dict-based checks
        result_dict = json.loads(result.to_json(deterministic_output=True))
        violations.extend(self.check_dict(result_dict))

        return violations


def deterministic_hash(result: ScanResult) -> str:  # rationale: include-list hashing, only hashes known-deterministic fields
    """SHA-256 hash of deterministic fields only.

    Excludes duration_ms and rule_timings_ms (timing is inherently
    non-deterministic). This is the canonical determinism fingerprint.

    Two scans of the same target with the same corpus MUST produce
    the same deterministic_hash, or the determinism guarantee is broken.
    """
    data = json.loads(result.to_json(deterministic_output=True))
    det: dict = {k: v for k, v in data.items() if k in DETERMINISTIC_FIELDS}
    # Strip non-deterministic timing fields from stats before hashing.
    if "stats" in det and isinstance(det["stats"], dict):
        det["stats"] = {k: v for k, v in det["stats"].items() if k not in ("duration_ms", "rule_timings_ms")}
    return hashlib.sha256(json.dumps(det, sort_keys=True).encode()).hexdigest()


def fingerprint_scan(result: ScanResult) -> str:
    """Stable fingerprint for caching and baselining.

    Shorter than deterministic_hash (16 chars vs 64), suitable for
    file names and human-readable identifiers.
    """
    return deterministic_hash(result)[:16]


def verify_determinism(
    result_a: ScanResult,
    result_b: ScanResult,
) -> tuple[bool, str, str]:
    """Compare two scan results for determinism.

    Uses the shared pico_core verify_determinism on computed hashes.
    """
    hash_a = deterministic_hash(result_a)
    hash_b = deterministic_hash(result_b)
    return _core_verify_determinism(hash_a, hash_b)


def diff_scans(
    path_a: Path,
    path_b: Path,
    verbose: bool = False,
) -> tuple[int, str]:
    """Compare two scan JSON files.

    PicoSentry uses DETERMINISTIC_FIELDS (include-list) for comparison,
    so audit/rule_status/timing fields are excluded from the hash.

    Returns (exit_code, output_message).
    Exit codes: 0=identical, 1=different, 2=error
    """
    if not path_a.is_file():
        return (2, f"Error: {path_a} does not exist")
    if not path_b.is_file():
        return (2, f"Error: {path_b} does not exist")

    try:
        data_a = json.loads(path_a.read_text(encoding="utf-8"))
        data_b = json.loads(path_b.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return (2, f"Error reading scan files: {e}")

    det_hash_a = _deterministic_hash_raw(data_a)
    det_hash_b = _deterministic_hash_raw(data_b)

    id_a = data_a.get("scan_id", "unknown")
    id_b = data_b.get("scan_id", "unknown")

    if det_hash_a == det_hash_b:
        lines = [
            "✓ Scans are IDENTICAL — determinism verified",
            f"  scan_id: {id_a}",
            f"  sha256:  {det_hash_a}",
            f"  findings: {len(data_a.get('findings', []))}",
        ]
        # Check if full JSON differs (timing only)
        full_hash_a = hashlib.sha256(json.dumps(data_a, sort_keys=True).encode()).hexdigest()
        full_hash_b = hashlib.sha256(json.dumps(data_b, sort_keys=True).encode()).hexdigest()
        if full_hash_a != full_hash_b:
            lines.append(
                f"  note: full JSON differs (timing: "
                f"{data_a.get('stats', {}).get('duration_ms', '?')}ms vs "
                f"{data_b.get('stats', {}).get('duration_ms', '?')}ms)"
            )
        return (0, "\n".join(lines))

    # Different — build diff output
    lines = [
        "✗ Scans DIFFER — determinism violation detected",
        f"  scan_a: id={id_a} sha256={det_hash_a[:16]}...",
        f"  scan_b: id={id_b} sha256={det_hash_b[:16]}...",
        f"  findings_a: {len(data_a.get('findings', []))}",
        f"  findings_b: {len(data_b.get('findings', []))}",
    ]

    # Compare metadata
    for key in sorted(set(list(data_a.keys()) + list(data_b.keys()))):
        if key == "findings":
            continue
        val_a = data_a.get(key)
        val_b = data_b.get(key)
        if val_a != val_b:
            lines.append(f"  {key}: {val_a!r} → {val_b!r}")

    if verbose:
        findings_a = data_a.get("findings", [])
        findings_b = data_b.get("findings", [])
        set_a = {(f["rule_id"], f["package"], f.get("line", 0)) for f in findings_a}
        set_b = {(f["rule_id"], f["package"], f.get("line", 0)) for f in findings_b}

        added = set_b - set_a
        removed = set_a - set_b

        if removed:
            lines.append(f"\n  Removed findings ({len(removed)}):")
            for rule_id, pkg, line in sorted(removed):
                lines.append(f"    - {rule_id} {pkg}:{line}")

        if added:
            lines.append(f"\n  Added findings ({len(added)}):")
            for rule_id, pkg, line in sorted(added):
                lines.append(f"    + {rule_id} {pkg}:{line}")

    return (1, "\n".join(lines))


def _deterministic_hash_raw(data: dict) -> str:
    """Hash raw scan JSON data (dict), excluding timing fields."""
    det = {k: v for k, v in data.items() if k in DETERMINISTIC_FIELDS}
    # Strip non-deterministic timing fields from stats before hashing.
    if "stats" in det and isinstance(det["stats"], dict):
        det["stats"] = {k: v for k, v in det["stats"].items() if k not in ("duration_ms", "rule_timings_ms")}
    return hashlib.sha256(json.dumps(det, sort_keys=True).encode()).hexdigest()
