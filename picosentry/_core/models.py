"""Shared enums and base dataclasses for the Pico Security Series.

Extracted from PicoDome and PicoSentry to provide a single source of truth
for common types used across all PicoSeries codebases.

- Verdict, Severity: canonical enums shared by all scanners/sandboxes
- Confidence: confidence level for findings
- ScanStats: aggregate statistics base with deterministic serialization
- FindingProtocol: minimum interface for cross-codebase finding objects
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class Severity(str, Enum):  # rationale: canonical severity shared across all 4 codebases via pico_core
    """Canonical severity levels across all PicoSeries tools."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Canonical severity ordering — use this instead of duplicating dicts.
SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class Verdict(str, Enum):  # rationale: canonical verdict for scan/sandbox results, shared via pico_core
    """Canonical verdict for scan/sandbox results."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    KILL = "KILL"


class Confidence(str, Enum):
    """Confidence level for findings."""

    EXACT = "EXACT"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class ScanStats:  # rationale: shared aggregate stats base, frozen for determinism
    """Aggregate statistics for a scan or analysis. Frozen for determinism.

    Shared base for both PicoDome SandboxResult.stats and PicoSentry ScanResult.stats.
    """

    packages_scanned: int = 0
    files_scanned: int = 0
    duration_ms: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_rule: dict[str, int] = field(default_factory=dict)

    def to_dict(self, deterministic: bool = False) -> dict:
        """Serialize to dict with sorted keys.

        In deterministic mode, omit duration_ms (timing is non-deterministic).
        """
        d: dict = {
            "packages_scanned": self.packages_scanned,
            "files_scanned": self.files_scanned,
            "findings_by_severity": dict(sorted(self.findings_by_severity.items())),
            "findings_by_rule": dict(sorted(self.findings_by_rule.items())),
        }
        if not deterministic:
            d["duration_ms"] = self.duration_ms
        return {k: v for k, v in sorted(d.items())}


@runtime_checkable
class FindingProtocol(Protocol):  # rationale: structural typing for cross-codebase finding objects
    """Minimum interface for finding objects across PicoSeries codebases.

    PicoDome.Finding, PicoSentry.Finding, and PicoWatch result types all
    satisfy this protocol structurally. Used for cross-codebase integration
    where the consumer only needs the common fields: rule_id, severity,
    and a way to serialize.

    This is a structural type — no inheritance required. Any object with
    these attributes automatically satisfies FindingProtocol.
    """

    rule_id: str
    severity: Severity

    def to_dict(self, deterministic: bool = ..., *, deterministic_output: bool = ...) -> dict[str, Any]: ...


__all__ = [
    "Severity",
    "SEVERITY_ORDER",
    "Verdict",
    "Confidence",
    "ScanStats",
    "FindingProtocol",
]
