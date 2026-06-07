
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum

from picosentry._core.models import FindingProtocol, Severity, Verdict
from picosentry._core.models import ScanStats as _ScanStats


__all__ = [
    "BehavioralVerdict",
    "Finding",
    "FindingProtocol",
    "ScanStats",
    "Severity",
    "Verdict",
    "_generate_finding_id",
    "_generate_run_id",
    "_generate_timestamp",
    "_now_iso",
    "_now_ms",
]


class BehavioralVerdict(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


@dataclass(frozen=True)
class Finding:  # rationale: sandbox finding, frozen for determinism, empty finding_id by default

    rule_id: str
    severity: Severity
    message: str
    location: str = ""
    evidence: dict = field(default_factory=dict)
    finding_id: str = ""

    def to_dict(self, deterministic: bool = False) -> dict:
        d: dict = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "location": self.location,
            "evidence": self.evidence,
        }
        if not deterministic and self.finding_id:
            d["finding_id"] = self.finding_id
        return {k: v for k, v in sorted(d.items())}


ScanStats = _ScanStats


def _now_ms() -> float:
    return time.monotonic() * 1000


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _generate_finding_id() -> str:
    return str(uuid.uuid4())


def _generate_run_id() -> str:
    return str(uuid.uuid4())


def _generate_timestamp() -> str:
    return _now_iso()
