
from __future__ import annotations

import hashlib
import json

from picosentry.sandbox import __version__
from picosentry.sandbox.l3.models import SandboxResult
from picosentry.sandbox.l4.models import AnalysisResult
from picosentry.sandbox.models import Severity


_SEVERITY_RATING = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}


def format_cyclonedx(result: SandboxResult | AnalysisResult) -> str:
    if isinstance(result, SandboxResult):
        return _l3_cyclonedx(result)
    return _l4_cyclonedx(result)


def _l3_cyclonedx(result: SandboxResult) -> str:

    det_timestamp = _deterministic_timestamp(__version__)


    vulns: list = []
    seen: set = set()
    for event in result.events:
        vuln_id = hashlib.sha256(f"{event.rule_id}:{event.operation}:{event.detail}".encode()).hexdigest()[:16]

        if vuln_id in seen:
            continue
        seen.add(vuln_id)

        vuln = {
            "bom-ref": vuln_id,
            "description": event.detail,
            "id": f"PICODOME-L3-{vuln_id[:8]}",
            "ratings": [
                {
                    "method": "other",
                    "severity": _severity_from_verdict(event.verdict.value),
                }
            ],
            "source": {
                "name": "PicoDome",
                "url": "https://github.com/KirkForge/PicoDome",
            },
        }
        vulns.append(vuln)


    root_name = " ".join(result.command) if result.command else result.policy_name or "unknown"

    bom = {
        "$schema": "https://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": det_timestamp,
            "tools": [
                {
                    "name": "PicoDome",
                    "vendor": "KirkForge",
                    "version": __version__,
                }
            ],
            "component": {
                "bom-ref": hashlib.sha256(root_name.encode()).hexdigest()[:16],
                "name": root_name,
                "type": "application",
            },
        },
        "vulnerabilities": vulns,
    }

    return json.dumps(bom, sort_keys=True, indent=2)


def _l4_cyclonedx(result: AnalysisResult) -> str:

    det_timestamp = _deterministic_timestamp(__version__)


    vulns: list = []
    seen: set = set()
    for f in result.findings:
        vuln_id = hashlib.sha256(f"{f.rule_id}:{f.message}:{f.location}".encode()).hexdigest()[:16]

        if vuln_id in seen:
            continue
        seen.add(vuln_id)

        vuln = {
            "bom-ref": vuln_id,
            "description": f.message,
            "id": f"PICODOME-L4-{vuln_id[:8]}",
            "ratings": [
                {
                    "method": "other",
                    "severity": _SEVERITY_RATING.get(f.severity, "info"),
                }
            ],
            "source": {
                "name": "PicoDome",
                "url": "https://github.com/KirkForge/PicoDome",
            },
        }

        if f.evidence:
            vuln["evidence"] = [{"description": str(f.evidence)}]

        vulns.append(vuln)


    root_name = result.target or "unknown"

    bom = {
        "$schema": "https://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": det_timestamp,
            "tools": [
                {
                    "name": "PicoDome",
                    "vendor": "KirkForge",
                    "version": __version__,
                }
            ],
            "component": {
                "bom-ref": hashlib.sha256(root_name.encode()).hexdigest()[:16],
                "name": root_name,
                "type": "application",
            },
        },
        "vulnerabilities": vulns,
    }

    return json.dumps(bom, sort_keys=True, indent=2)


def _severity_from_verdict(verdict: str) -> str:
    mapping = {
        "ALLOW": "info",
        "DENY": "high",
        "KILL": "critical",
    }
    return mapping.get(verdict, "info")


def _deterministic_timestamp(version: str) -> str:

    try:
        parts = version.replace("v", "").split(".")
        major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
        offset_hours = (major * 100 + minor * 10 + patch) % 8760
    except (ValueError, IndexError):
        offset_hours = 0

    day = (offset_hours // 24) % 28 + 1
    hour = offset_hours % 24
    return f"2025-01-{day:02d}T{hour:02d}:00:00Z"
