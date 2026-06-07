
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):

    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True)
class PromptScanResult:  # rationale: L5 prompt scan result, frozen for determinism

    blocked: bool
    score: float
    rules_matched: list[str]
    corpus_hash: str
    corpus_version: str
    duration_ms: float
    verdict: Verdict = Verdict.PASS
    normalized_input: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    threshold_block: float = 0.7
    threshold_warn: float = 0.4

    def __post_init__(self) -> None:

        if self.score != round(self.score, 6):
            object.__setattr__(self, "score", round(self.score, 6))

        if self.blocked or self.score >= self.threshold_block:
            object.__setattr__(self, "verdict", Verdict.BLOCK)
        elif self.score >= self.threshold_warn:
            object.__setattr__(self, "verdict", Verdict.WARN)
        else:
            object.__setattr__(self, "verdict", Verdict.PASS)


@dataclass(frozen=True)
class ValidationResult:  # rationale: L6 output validation result, frozen for determinism

    valid: bool
    score: float
    violations: list[str]
    corpus_hash: str
    corpus_version: str
    duration_ms: float
    verdict: Verdict = Verdict.PASS
    redacted: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    threshold_block: float = 0.7
    threshold_warn: float = 0.4

    def __post_init__(self) -> None:
        if self.score != round(self.score, 6):
            object.__setattr__(self, "score", round(self.score, 6))
        if not self.valid or self.score >= self.threshold_block:
            object.__setattr__(self, "verdict", Verdict.BLOCK)
        elif self.score >= self.threshold_warn:
            object.__setattr__(self, "verdict", Verdict.WARN)
        else:
            object.__setattr__(self, "verdict", Verdict.PASS)


@dataclass(frozen=True)
class Rule:

    id: str
    category: str
    weight: float
    pattern: str
    description: str
    normalization: list[str] = field(default_factory=lambda: ["unicode", "whitespace"])

    def __post_init__(self) -> None:
        if self.weight < 0.0 or self.weight > 1.0:
            raise ValueError(f"Rule weight must be 0.0-1.0, got {self.weight}")

        if self.weight != round(self.weight, 4):
            object.__setattr__(self, "weight", round(self.weight, 4))


@dataclass(frozen=True)
class HealthStatus:

    healthy: bool
    version: str
    rules_loaded: int
    corpus_hash: str
    corpus_version: str
    uptime_seconds: float = 0.0
    rules_expected: int = 0
    load_errors: list[str] = field(default_factory=list)
