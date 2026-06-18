
from __future__ import annotations


import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from picosentry._core.models import SEVERITY_ORDER, Confidence, FindingProtocol, Severity


__all__ = [
    "SEVERITY_ORDER",
    "BaselineResult",
    "Confidence",
    "Finding",
    "FindingProtocol",
    "RuleExecution",
    "ScanResult",
    "ScanStats",
    "Severity",
    "apply_baseline",
    "load_baseline",
]


@dataclass
class ScanStats:

    packages_scanned: int = 0
    files_scanned: int = 0
    duration_ms: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_rule: dict[str, int] = field(default_factory=dict)
    rule_timings_ms: dict[str, int] = field(default_factory=dict)

    def to_dict(self, deterministic: bool = False) -> dict[str, Any]:
        d = {
            "packages_scanned": self.packages_scanned,
            "files_scanned": self.files_scanned,
            "findings_by_severity": dict(sorted(self.findings_by_severity.items())),
            "findings_by_rule": dict(sorted(self.findings_by_rule.items())),
        }
        if not deterministic:
            d["duration_ms"] = self.duration_ms
        if self.rule_timings_ms:
            d["rule_timings_ms"] = dict(sorted(self.rule_timings_ms.items()))
        return d


@dataclass(frozen=True)
class Finding:  # rationale: immutable scan finding, frozen for determinism guarantee

    rule_id: str
    severity: Severity
    confidence: Confidence
    package: str
    file: str
    message: str
    evidence: str
    remediation: str
    references: list[str] = field(default_factory=list)
    line: int | None = None
    ecosystem: str = "npm"

    def fingerprint(self) -> tuple:
        return (self.rule_id, self.ecosystem, self.package, self.file)

    def sort_key(self) -> tuple:
        return (self.rule_id, self.ecosystem, self.package, self.file, self.line or 0)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "ecosystem": self.ecosystem,
            "package": self.package,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }
        if self.references:
            d["references"] = self.references
        return d


@dataclass
class BaselineResult:

    original_count: int = 0
    suppressed_count: int = 0
    remaining: list[Finding] = field(default_factory=list)

    @property
    def new_count(self) -> int:
        return len(self.remaining)


def load_baseline(path: Path) -> set:
    text = path.read_text(encoding="utf-8")


    try:
        data = json.loads(text)
        if "findings" in data:
            fingerprints = set()
            for f in data["findings"]:
                key = (
                    f.get("rule_id", ""),
                    f.get("ecosystem", "npm"),
                    f.get("package", ""),
                    f.get("file", ""),
                )
                fingerprints.add(key)
            return fingerprints
    except json.JSONDecodeError:
        pass


    fingerprints = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 3)

        if parts[0] in {"npm", "pypi", "go", "cargo", "maven", "rubygems", "nuget"}:
            ecosystem = parts[0].strip()
            rule_id = parts[1].strip() if len(parts) > 1 else ""
            package = parts[2].strip() if len(parts) > 2 else ""
            file_p = parts[3].strip() if len(parts) > 3 else ""
        else:
            ecosystem = "npm"
            rule_id = parts[0].strip()
            package = parts[1].strip() if len(parts) > 1 else ""
            file_p = parts[2].strip() if len(parts) > 2 else ""
        fingerprints.add((rule_id, ecosystem, package, file_p))

    return fingerprints


def apply_baseline(result: ScanResult, baseline_fingerprints: set) -> BaselineResult:

    normalized: set[tuple[str, str, str, str]] = set()
    for fp in baseline_fingerprints:
        if len(fp) == 3:
            normalized.add((fp[0], "npm", fp[1], fp[2]))
        else:
            normalized.add((fp[0], fp[1], fp[2], fp[3]))


    rule_only = {fp[0] for fp in normalized if not fp[2]}
    rule_ecosystem_pkg = {(fp[0], fp[1], fp[2]) for fp in normalized if fp[2] and not fp[3]}
    exact = {fp for fp in normalized if fp[3]}

    remaining = []
    for f in result.findings:
        fp = f.fingerprint()
        if fp in exact:
            continue
        if (fp[0], fp[1], fp[2]) in rule_ecosystem_pkg:
            continue
        if fp[0] in rule_only:
            continue
        remaining.append(f)

    return BaselineResult(
        original_count=len(result.findings),
        suppressed_count=len(result.findings) - len(remaining),
        remaining=remaining,
    )


@dataclass
class RuleExecution:

    rule_id: str
    status: str = "success"  # "success", "failed", "skipped"
    duration_ms: int = 0
    error: str = ""
    files_scanned: int = 0
    findings_count: int = 0

    def to_dict(self, deterministic_output: bool = False) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rule_id": self.rule_id,
            "status": self.status,
            "findings_count": self.findings_count,
            "files_scanned": self.files_scanned,
        }
        if not deterministic_output:
            d["duration_ms"] = self.duration_ms
            if self.error:
                d["error"] = self.error
        return d


@dataclass
class ScanResult:  # rationale: top-level scan result, deterministic by construction

    target: str = ""
    engine_version: str = ""  # Set by ScanEngine from __version__
    corpus_version: str = ""  # Set by ScanEngine from corpus hash
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    started_at: str = ""
    completed_at: str = ""
    config_digest: str = ""
    policy_digest: str = ""
    scanner_version: str = ""
    policy_result: Any = None
    rule_executions: list[RuleExecution] = field(default_factory=list)

    def recompute_stats(self) -> None:
        by_sev: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        for f in self.findings:
            sev = f.severity.value
            by_sev[sev] = by_sev.get(sev, 0) + 1
            by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        self.stats.findings_by_severity = dict(sorted(by_sev.items()))
        self.stats.findings_by_rule = dict(sorted(by_rule.items()))

    def apply_overrides(self, findings: list) -> ScanResult:
        self.findings = findings
        self.recompute_stats()
        return self

    @property
    def scan_id(self) -> str:
        raw = f"{self.target}:{self.corpus_version}:{self.engine_version}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self, deterministic_output: bool = False) -> dict[str, Any]:
        sorted_findings = sorted(self.findings, key=lambda f: f.sort_key())

        d: dict[str, Any] = {
            "scan_id": self.scan_id,
            "engine_version": self.engine_version,
            "corpus_version": self.corpus_version,
            "target": self.target,
            "findings": [f.to_dict() for f in sorted_findings],
        }


        if not deterministic_output:
            d["stats"] = self.stats.to_dict()
        else:
            d["stats"] = {
                "packages_scanned": self.stats.packages_scanned,
                "files_scanned": self.stats.files_scanned,
                "findings_by_severity": dict(sorted(self.stats.findings_by_severity.items())),
                "findings_by_rule": dict(sorted(self.stats.findings_by_rule.items())),
            }
        if self.rule_executions:
            d["rule_status"] = {
                r.rule_id: r.to_dict(deterministic_output=deterministic_output) for r in self.rule_executions
            }
            any_failed = any(r.status == "failed" for r in self.rule_executions)
            d["scan_completeness"] = "partial" if any_failed else "complete"
        if self.policy_result is not None and hasattr(self.policy_result, "to_dict"):
            d["policy"] = self.policy_result.to_dict()

        if not deterministic_output:
            audit = {}
            if self.started_at:
                audit["started_at"] = self.started_at
            if self.completed_at:
                audit["completed_at"] = self.completed_at
            if self.config_digest:
                audit["config_digest"] = self.config_digest
            if self.policy_digest:
                audit["policy_digest"] = self.policy_digest
            if self.scanner_version:
                audit["scanner_version"] = self.scanner_version
            if audit:
                d["audit"] = audit


        return dict(sorted(d.items()))

    def to_json(self, indent: int = 2, deterministic_output: bool = False) -> str:
        return json.dumps(self.to_dict(deterministic_output=deterministic_output), sort_keys=True, indent=indent)

    def to_ml_context(self, token_budget: int = 4096) -> str:
        sorted_findings = sorted(self.findings, key=lambda f: f.sort_key())
        lines = [
            f"scan_id={self.scan_id}",
            f"corpus_version={self.corpus_version}",
            f"target={self.target}",
            f"findings={len(sorted_findings)}",
            "",
        ]
        for f in sorted_findings:
            line = f"[{f.severity.value}] {f.rule_id} ({f.ecosystem}) {f.package} {f.file}"
            if f.line:
                line += f":{f.line}"
            line += f" | {f.evidence}"
            lines.append(line)

        output = "\n".join(lines)
        if len(output) > token_budget * 4:
            output = output[: token_budget * 4] + "\n[TRUNCATED]"
        return output
