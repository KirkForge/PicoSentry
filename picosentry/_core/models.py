
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class Severity(str, Enum):

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class Verdict(str, Enum):

    ALLOW = "ALLOW"
    DENY = "DENY"
    KILL = "KILL"


class Confidence(str, Enum):

    EXACT = "EXACT"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class ScanStats:

    packages_scanned: int = 0
    files_scanned: int = 0
    duration_ms: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_rule: dict[str, int] = field(default_factory=dict)

    def to_dict(self, deterministic: bool = False) -> dict:
        d: dict = {
            "packages_scanned": self.packages_scanned,
            "files_scanned": self.files_scanned,
            "findings_by_severity": dict(sorted(self.findings_by_severity.items())),
            "findings_by_rule": dict(sorted(self.findings_by_rule.items())),
        }
        if not deterministic:
            d["duration_ms"] = self.duration_ms
        return dict(sorted(d.items()))


@runtime_checkable
class FindingProtocol(Protocol):

    rule_id: str
    severity: Severity

    def to_dict(self, deterministic: bool = ..., *, deterministic_output: bool = ...) -> dict[str, Any]: ...


__all__ = [
    "SEVERITY_ORDER",
    "Confidence",
    "FindingProtocol",
    "ScanStats",
    "Severity",
    "Verdict",
]
