import json
from typing import Any

from picosentry.scan.models import ScanResult, Severity
from picosentry.scan.rules import RULE_INFO


SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def format_sarif(result: ScanResult) -> str:
    rules_seen = {}
    results = []

    for finding in sorted(result.findings, key=lambda f: f.sort_key()):
        if finding.rule_id not in rules_seen:
            info = RULE_INFO.get(finding.rule_id, {})
            rule_def = {
                "id": finding.rule_id,
                "name": info.get("name", finding.rule_id.lower().replace("l2-", "")),
                "shortDescription": {"text": info.get("description", finding.message)},
                "properties": {
                    "security-severity": finding.severity.value,
                    "category": info.get("category", "unknown"),
                },
            }

            help_uri = info.get("helpUri")
            if help_uri:
                rule_def["helpUri"] = help_uri
            rules_seen[finding.rule_id] = rule_def

    sorted_rule_ids = sorted(rules_seen.keys())
    rule_index = {rid: idx for idx, rid in enumerate(sorted_rule_ids)}

    for finding in sorted(result.findings, key=lambda f: f.sort_key()):
        properties: dict[str, Any] = {
            "package": finding.package,
            "confidence": finding.confidence.value,
            "ecosystem": finding.ecosystem,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
        }
        if finding.references:
            properties["references"] = finding.references
        result_entry: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index[finding.rule_id],
            "level": SEVERITY_MAP.get(finding.severity, "warning"),
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file},
                        "region": {"startLine": finding.line or 1},
                    }
                }
            ],
            "properties": properties,
        }

        results.append(result_entry)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "picosentry",
                        "version": result.engine_version,
                        "informationUri": "https://github.com/KirkForge/PicoSentry",
                        "rules": [rules_seen[rid] for rid in sorted(rules_seen.keys())],
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "engine_version": result.engine_version,
                            "corpus_version": result.corpus_version,
                            "scan_completeness": "complete"
                            if all(r.status == "ok" for r in getattr(result, "rule_executions", []))
                            else "partial",
                        },
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif, sort_keys=True, indent=2)
