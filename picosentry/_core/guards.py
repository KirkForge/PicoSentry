from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


UUID_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
ISO_TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


FORBIDDEN_IN_FINDINGS = frozenset(
    {
        "uuid4",
        "uuid.uuid4",
        "random()",
        "datetime.now()",
        "time.time()",
    }
)

_DEFAULT_EXCLUDE_FIELDS = ("run_id", "timestamp", "duration_ms", "scan_id")


@runtime_checkable
class DeterministicResult(Protocol):
    def to_dict(self, deterministic: bool = ..., *, deterministic_output: bool = ...) -> dict[str, Any]: ...


class DeterminismViolation(Exception):
    def __init__(self, violations: list[str]):
        self.violations = violations
        super().__init__(f"Determinism violation(s): {len(violations)}\n" + "\n".join(f"  - {v}" for v in violations))


class DeterministicGuard:
    def check_dict(self, result_dict: dict[str, Any]) -> list[str]:
        violations: list[str] = []
        _check_value(result_dict, violations, path="result")
        return violations

    def check_findings(self, findings: list[dict[str, Any]]) -> list[str]:
        violations: list[str] = []

        for i, f in enumerate(findings):
            path = f"findings[{i}]"

            for field_name in ("evidence", "message", "remediation"):
                val = f.get(field_name, "")
                if not isinstance(val, str):
                    continue
                violations.extend(
                    f"{path}.{field_name} contains forbidden pattern '{pattern}'"
                    for pattern in FORBIDDEN_IN_FINDINGS
                    if pattern in val
                )

            for field_name in ("finding_id", "rule_id", "package"):
                val = f.get(field_name, "")
                if not isinstance(val, str):
                    continue
                if field_name == "finding_id" and UUID_PATTERN.fullmatch(val):
                    violations.append(f"{path}.{field_name} is a UUID (non-deterministic): {val}")

            if not f.get("rule_id"):
                violations.append(f"{path} missing rule_id")

        if findings:
            keys = [
                (f.get("rule_id", ""), f.get("package", ""), f.get("file", ""), f.get("line") or 0) for f in findings
            ]
            if keys != sorted(keys):
                violations.append("findings not sorted by (rule_id, package, file, line)")

        fingerprints = [(f.get("rule_id", ""), f.get("package", ""), f.get("file", "")) for f in findings]
        if len(fingerprints) != len(set(fingerprints)):
            violations.append("duplicate findings detected (same rule_id, package, file)")

        return violations


def deterministic_hash(
    data: dict[str, Any],
    exclude_fields: tuple[str, ...] = _DEFAULT_EXCLUDE_FIELDS,
) -> str:
    det = {k: v for k, v in data.items() if k not in exclude_fields}

    if "stats" in det and isinstance(det["stats"], dict):
        det["stats"] = {k: v for k, v in det["stats"].items() if k not in ("duration_ms", "rule_timings_ms")}
    return hashlib.sha256(json.dumps(det, sort_keys=True).encode()).hexdigest()


def verify_determinism(hash_a: str, hash_b: str) -> tuple[bool, str, str]:
    return (hash_a == hash_b, hash_a, hash_b)


def diff_results(
    path_a: Path,
    path_b: Path,
    verbose: bool = False,
    id_field: str = "scan_id",
    findings_key: str = "findings",
    exclude_fields: tuple[str, ...] = ("run_id", "timestamp", "duration_ms", "scan_id"),
) -> tuple[int, str]:
    if not path_a.is_file():
        return (2, f"Error: {path_a} does not exist")
    if not path_b.is_file():
        return (2, f"Error: {path_b} does not exist")

    try:
        data_a = json.loads(path_a.read_text(encoding="utf-8"))
        data_b = json.loads(path_b.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return (2, f"Error reading result files: {e}")

    det_hash_a = _deterministic_hash_raw(data_a, exclude_fields=exclude_fields)
    det_hash_b = _deterministic_hash_raw(data_b, exclude_fields=exclude_fields)

    id_a = data_a.get(id_field, "unknown")
    id_b = data_b.get(id_field, "unknown")

    if det_hash_a == det_hash_b:
        lines = [
            "✓ Results are IDENTICAL — determinism verified",
            f"  {id_field}: {id_a}",
            f"  sha256:  {det_hash_a}",
            f"  {findings_key}: {len(data_a.get(findings_key, []))}",
        ]

        full_hash_a = hashlib.sha256(json.dumps(data_a, sort_keys=True).encode()).hexdigest()
        full_hash_b = hashlib.sha256(json.dumps(data_b, sort_keys=True).encode()).hexdigest()
        if full_hash_a != full_hash_b:
            timing_a = data_a.get("duration_ms") or data_a.get("stats", {}).get("duration_ms", "?")
            timing_b = data_b.get("duration_ms") or data_b.get("stats", {}).get("duration_ms", "?")
            lines.append(f"  note: full JSON differs (timing: {timing_a}ms vs {timing_b}ms)")
        return (0, "\n".join(lines))

    lines = [
        "✗ Results DIFFER — determinism violation detected",
        f"  result_a: {id_field}={id_a} sha256={det_hash_a[:16]}...",
        f"  result_b: {id_field}={id_b} sha256={det_hash_b[:16]}...",
        f"  {findings_key}_a: {len(data_a.get(findings_key, []))}",
        f"  {findings_key}_b: {len(data_b.get(findings_key, []))}",
    ]

    for key in sorted(set(list(data_a.keys()) + list(data_b.keys()))):
        if key == findings_key:
            continue
        val_a = data_a.get(key)
        val_b = data_b.get(key)
        if val_a != val_b:
            lines.append(f"  {key}: {val_a!r} → {val_b!r}")

    if verbose:
        findings_a = data_a.get(findings_key, [])
        findings_b = data_b.get(findings_key, [])

        def _finding_fingerprint(f: dict) -> tuple:
            return (
                f.get("rule_id", ""),
                f.get("package", ""),
                f.get("file", ""),
                f.get("line", 0) or 0,
            )

        set_a = {_finding_fingerprint(f) for f in findings_a}
        set_b = {_finding_fingerprint(f) for f in findings_b}

        added = set_b - set_a
        removed = set_a - set_b

        if removed:
            lines.append(f"\n  Removed findings ({len(removed)}):")
            for fp in sorted(removed):
                lines.append(f"    - {fp[0]} {fp[1]}:{fp[2]}:{fp[3]}")

        if added:
            lines.append(f"\n  Added findings ({len(added)}):")
            for fp in sorted(added):
                lines.append(f"    + {fp[0]} {fp[1]}:{fp[2]}:{fp[3]}")

    return (1, "\n".join(lines))


def _deterministic_hash_raw(
    data: dict,
    exclude_fields: tuple[str, ...] = _DEFAULT_EXCLUDE_FIELDS,
) -> str:
    det = {k: v for k, v in data.items() if k not in exclude_fields}
    if "stats" in det and isinstance(det["stats"], dict):
        det["stats"] = {k: v for k, v in det["stats"].items() if k not in ("duration_ms", "rule_timings_ms")}
    return hashlib.sha256(json.dumps(det, sort_keys=True).encode()).hexdigest()


def _check_value(value: Any, violations: list[str], path: str) -> None:
    if isinstance(value, str):
        if UUID_PATTERN.search(value):
            violations.append(f"UUID found in {path}: {value[:80]}")
        if ISO_TIMESTAMP_PATTERN.search(value):
            violations.append(f"ISO timestamp found in {path}: {value[:80]}")
    elif isinstance(value, dict):
        if list(value.keys()) != sorted(value.keys()):
            violations.append(f"Dict keys not sorted in {path}")
        for k, v in value.items():
            _check_value(v, violations, f"{path}[{k}]")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _check_value(item, violations, f"{path}[{i}]")


__all__ = [
    "FORBIDDEN_IN_FINDINGS",
    "ISO_TIMESTAMP_PATTERN",
    "UUID_PATTERN",
    "DeterminismViolation",
    "DeterministicGuard",
    "DeterministicResult",
    "deterministic_hash",
    "diff_results",
    "verify_determinism",
]
