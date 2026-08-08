from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from picosentry import __version__
from picosentry._core.models import Severity
from picosentry.scan.rules import RULE_INFO

if TYPE_CHECKING:
    from picosentry.scan.models import Finding, ScanResult

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _finding_fingerprint(finding: Finding) -> str:
    raw = f"{finding.rule_id}:{finding.ecosystem}:{finding.package}:{finding.file}:{finding.line or 0}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _finding_location(finding: Finding) -> dict[str, Any]:
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": finding.file},
            "region": {"startLine": finding.line or 1},
        }
    }
    return location


def _rule_descriptor(rule_id: str, finding: Finding) -> dict[str, Any]:
    info = RULE_INFO.get(rule_id, {})
    descriptor: dict[str, Any] = {
        "id": rule_id,
        "name": info.get("name", rule_id.lower().replace("l2-", "")),
        "shortDescription": {"text": info.get("description", finding.message)},
        "properties": {
            "security-severity": finding.severity.value,
            "category": info.get("category", "unknown"),
        },
    }
    help_uri = info.get("helpUri")
    if help_uri:
        descriptor["helpUri"] = help_uri
    return descriptor


@dataclass
class SarifFormatter:
    result: ScanResult
    _rules_seen: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)

    def _collect_rules(self) -> list[dict[str, Any]]:
        for finding in sorted(self.result.findings, key=lambda f: f.sort_key()):
            if finding.rule_id not in self._rules_seen:
                self._rules_seen[finding.rule_id] = _rule_descriptor(finding.rule_id, finding)
        return [self._rules_seen[rid] for rid in sorted(self._rules_seen)]

    def _build_results(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for finding in sorted(self.result.findings, key=lambda f: f.sort_key()):
            entry: dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": _SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
                "message": {"text": finding.message},
                "locations": [_finding_location(finding)],
                "fingerprints": {"primaryLocationLineHash": _finding_fingerprint(finding)},
            }
            props: dict[str, Any] = {
                "package": finding.package,
                "confidence": finding.confidence.value,
                "ecosystem": finding.ecosystem,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
            }
            if finding.references:
                props["references"] = finding.references
            entry["properties"] = props
            out.append(entry)
        return out

    def _build_invocations(self) -> list[dict[str, Any]]:
        executions = getattr(self.result, "rule_executions", None) or []
        failed = [r for r in executions if r.status == "failed"]
        timed_out = [r for r in executions if r.status == "timeout"]
        notifications: list[dict[str, Any]] = []
        for r in failed:
            notifications.append(
                {
                    "descriptor": {"id": f"rule/{r.rule_id}/error"},
                    "level": "error",
                    "message": {"text": r.error or f"Rule {r.rule_id} failed"},
                }
            )
        for r in timed_out:
            notifications.append(
                {
                    "descriptor": {"id": f"rule/{r.rule_id}/timeout"},
                    "level": "warning",
                    "message": {"text": r.error or f"Rule {r.rule_id} timed out"},
                }
            )
        invocation: dict[str, Any] = {
            "executionSuccessful": not failed,
            "properties": {
                "engine_version": self.result.engine_version,
                "corpus_version": self.result.corpus_version,
            },
        }
        if notifications:
            invocation["toolExecutionNotifications"] = notifications
        return [invocation]

    def format(self) -> str:
        run: dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": "PicoSentry",
                    "version": self.result.engine_version or __version__,
                    "informationUri": "https://github.com/KirkForge/PicoSentry",
                    "rules": self._collect_rules(),
                }
            },
            "results": self._build_results(),
            "invocations": self._build_invocations(),
        }
        if self.result.behavioral_evidence:
            run["properties"] = {"behavioral_evidence": self.result.behavioral_evidence}
        sarif: dict[str, Any] = {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [run],
        }
        return json.dumps(sarif, sort_keys=True, indent=2)


def format_sarif(result: ScanResult) -> str:
    return SarifFormatter(result).format()
