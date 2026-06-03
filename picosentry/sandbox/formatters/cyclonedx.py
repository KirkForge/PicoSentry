"""CycloneDX SBOM formatter — enterprise standard for Software Bill of Materials.

Produces CycloneDX 1.5 JSON compatible with dependency-track, OWASP tools,
and enterprise procurement pipelines.

Deterministic: same target + same findings = same CycloneDX output.
Timestamp is derived from a deterministic epoch, not wall-clock time.
"""

from __future__ import annotations

import hashlib
import json

from picosentry.sandbox import __version__
from picosentry.sandbox.l3.models import SandboxResult
from picosentry.sandbox.l4.models import AnalysisResult
from picosentry.sandbox.models import Severity

# Severity to CycloneDX severity rating mapping
_SEVERITY_RATING = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}


def format_cyclonedx(result: SandboxResult | AnalysisResult) -> str:
    """
    Format a result as CycloneDX 1.5 JSON.

    Produces a vulnerability-oriented SBOM with findings mapped to
    CycloneDX vulnerability objects.

    Deterministic: sorted keys, deterministic timestamp, no random IDs.

    Args:
        result: SandboxResult or AnalysisResult to format.

    Returns:
        CycloneDX 1.5 JSON string.
    """
    if isinstance(result, SandboxResult):
        return _l3_cyclonedx(result)
    return _l4_cyclonedx(result)


def _l3_cyclonedx(result: SandboxResult) -> str:
    """Format L3 sandbox result as CycloneDX 1.5 JSON."""
    # Deterministic timestamp: fixed epoch anchored to version
    det_timestamp = _deterministic_timestamp(__version__)

    # Build vulnerabilities from sandbox events
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

    # Root component
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
    """Format L4 analysis result as CycloneDX 1.5 JSON."""
    # Deterministic timestamp: fixed epoch anchored to version
    det_timestamp = _deterministic_timestamp(__version__)

    # Build vulnerabilities from findings
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

    # Root component
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
    """Map PicoDome verdict to CycloneDX severity."""
    mapping = {
        "ALLOW": "info",
        "DENY": "high",
        "KILL": "critical",
    }
    return mapping.get(verdict, "info")


def _deterministic_timestamp(version: str) -> str:
    """Generate a deterministic ISO 8601 timestamp from version string.

    Uses a fixed epoch date + version-based offset to produce a stable
    timestamp that changes only when the version changes. Not wall-clock time.
    """
    # Parse version components for offset
    try:
        parts = version.replace("v", "").split(".")
        major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
        offset_hours = (major * 100 + minor * 10 + patch) % 8760
    except (ValueError, IndexError):
        offset_hours = 0

    day = (offset_hours // 24) % 28 + 1
    hour = offset_hours % 24
    return f"2025-01-{day:02d}T{hour:02d}:00:00Z"
