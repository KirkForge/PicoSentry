
from __future__ import annotations

import json

from picosentry.sandbox import __version__
from picosentry.sandbox.l3.models import SandboxResult
from picosentry.sandbox.l4.models import AnalysisResult


def format_sarif(result: SandboxResult | AnalysisResult) -> str:
    if isinstance(result, SandboxResult):
        return _l3_sarif(result)
    return _l4_sarif(result)


def _l3_sarif(result: SandboxResult) -> str:
    results = [
        {
            "level": _severity_to_sarif(event.verdict.value),
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": event.path or "unknown"},
                        "region": {"startLine": 1},
                    }
                }
            ]
            if event.path
            else [],
            "message": {"text": event.detail},
            "properties": {
                "operation": event.operation,
                "address": event.address,
            },
            "ruleId": event.rule_id,
        }
        for event in result.events
    ]


    seen_rules: dict[str, dict] = {}
    for e in result.events:
        if e.rule_id not in seen_rules:
            seen_rules[e.rule_id] = {
                "id": e.rule_id,
                "shortDescription": {"text": e.operation},
            }

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "properties": {
                    "backend": result.backend_name,
                    "command": result.command,
                    "duration_ms": result.duration_ms,
                    "exit_code": result.exit_code,
                    "overall_verdict": result.overall_verdict.value,
                    "policy": result.policy_name,
                    "policy_hash": result.policy_hash,
                    "policy_version": result.policy_version,
                },
                "results": results,
                "tool": {
                    "driver": {
                        "informationUri": "https://github.com/KirkForge/PicoDome",
                        "name": "PicoDome",
                        "rules": list(seen_rules.values()),
                        "version": __version__,
                    }
                },
            }
        ],
        "version": "2.1.0",
    }
    return json.dumps(sarif, indent=2, default=str, sort_keys=True)


def _l4_sarif(result: AnalysisResult) -> str:
    results = [
        {
            "level": _severity_to_sarif(finding.severity.value),
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.location or "unknown"},
                    }
                }
            ],
            "message": {"text": finding.message},
            "properties": finding.evidence,
            "ruleId": finding.rule_id,
        }
        for finding in result.findings
    ]

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "properties": {
                    "overall_verdict": result.overall_verdict.value,
                    "target": result.target,
                },
                "results": results,
                "tool": {
                    "driver": {
                        "informationUri": "https://github.com/KirkForge/PicoDome",
                        "name": "PicoDome",
                        "version": __version__,
                    }
                },
            }
        ],
        "version": "2.1.0",
    }
    return json.dumps(sarif, indent=2, default=str, sort_keys=True)


def _severity_to_sarif(severity: str) -> str:
    mapping = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "none",
        "ALLOW": "none",
        "DENY": "error",
        "KILL": "error",
    }
    return mapping.get(severity, "warning")
