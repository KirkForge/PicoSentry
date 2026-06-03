"""
CycloneDX SBOM formatter — enterprise standard for Software Bill of Materials.

Produces CycloneDX 1.5 JSON compatible with dependency-track, OWASP tools,
and enterprise procurement pipelines.

Deterministic: same target + same corpus = same CycloneDX SBOM.
Timestamp is derived from the deterministic scan_id, not wall-clock time.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from picosentry.scan.models import ScanResult, Severity
from picosentry.scan.rules.utils import load_package_json

# PURL prefix for npm packages
_PURL_PREFIX = "pkg:npm"


def _walk_node_modules(target: Path) -> list[dict]:
    """Walk node_modules and build CycloneDX component inventory.

    Returns a sorted list of component dicts with type, name, version,
    bom-ref, purl, and integrity hash (when available from package.json).
    Deterministic: sorted by name.
    """
    components: dict[str, dict] = {}
    nm = target / "node_modules"
    if not nm.is_dir():
        return []

    for child in sorted(nm.iterdir()):
        if not child.is_dir() or child.name.startswith("."):
            continue

        pkg_json = child / "package.json"
        if pkg_json.is_file():
            pkg = load_package_json(pkg_json)
            if pkg:
                name = pkg.get("name", child.name)
                version = pkg.get("version", "unknown")
                key = name
                if key not in components:
                    comp = {
                        "type": "library",
                        "name": name,
                        "version": version,
                        "bom-ref": hashlib.sha256(f"{name}@{version}".encode()).hexdigest()[:16],
                        "purl": f"{_PURL_PREFIX}/{name}@{version}",
                    }
                    # Include integrity hash if present in pkg
                    if "dist" in pkg and isinstance(pkg["dist"], dict):
                        shasum = pkg["dist"].get("shasum", "")
                        integrity = pkg["dist"].get("integrity", "")
                        if integrity:
                            algo, _, hash_val = integrity.partition("-")
                            comp["hashes"] = [{"alg": algo.upper(), "content": hash_val}]
                        elif shasum:
                            comp["hashes"] = [{"alg": "SHA-1", "content": shasum}]
                    components[key] = comp

        # Scoped packages: node_modules/@scope/pkg
        if child.name.startswith("@") and child.is_dir():
            for scoped_child in sorted(child.iterdir()):
                if not scoped_child.is_dir():
                    continue
                scoped_pkg = scoped_child / "package.json"
                if scoped_pkg.is_file():
                    pkg = load_package_json(scoped_pkg)
                    if pkg:
                        name = pkg.get("name", f"{child.name}/{scoped_child.name}")
                        version = pkg.get("version", "unknown")
                        key = name
                        if key not in components:
                            comp = {
                                "type": "library",
                                "name": name,
                                "version": version,
                                "bom-ref": hashlib.sha256(f"{name}@{version}".encode()).hexdigest()[:16],
                                "purl": f"{_PURL_PREFIX}/{name.replace('/', '%2F')}@{version}",
                            }
                            if "dist" in pkg and isinstance(pkg["dist"], dict):
                                integrity = pkg["dist"].get("integrity", "")
                                if integrity:
                                    algo, _, hash_val = integrity.partition("-")
                                    comp["hashes"] = [{"alg": algo.upper(), "content": hash_val}]
                            components[key] = comp

    return sorted(components.values(), key=lambda c: c["name"])


def format_cyclonedx(result: ScanResult) -> str:
    """Format ScanResult as CycloneDX 1.5 JSON SBOM.

    Produces a full SBOM with component inventory (walked from node_modules)
    and vulnerability entries mapped from PicoSentry findings.

    Deterministic: deterministic timestamp (derived from scan_id),
    sorted components, sorted vulnerabilities. No wall-clock time.
    """
    _SEVERITY_RATING = {
        Severity.CRITICAL: "critical",
        Severity.HIGH: "high",
        Severity.MEDIUM: "medium",
        Severity.LOW: "low",
        Severity.INFO: "info",
    }

    _CONFIDENCE_SCORE = {
        "EXACT": 1.0,
        "HIGH": 0.8,
        "MEDIUM": 0.5,
        "LOW": 0.2,
    }

    # Deterministic timestamp derived from scan_id (already sha256 of target+corpus+engine).
    # Uses hex digits of scan_id to produce a stable ISO 8601 timestamp
    # that changes only when the scan inputs change.  Not wall-clock time.
    _sid = result.scan_id  # sha256-based, 16 hex chars
    det_timestamp = f"20{_sid[:2]}-{_sid[2:4]}-{_sid[4:6]}T{_sid[6:8]}:{_sid[8:10]}:{_sid[10:12]}Z"

    # Walk node_modules for real component inventory
    target_path = Path(result.target)
    components = _walk_node_modules(target_path)

    # Build component name → bom-ref lookup for vulnerability affects
    comp_refs: dict[str, str] = {c["name"]: c["bom-ref"] for c in components}

    # Build vulnerabilities from findings
    vulns: list[dict] = []
    seen_vulns: set[tuple] = set()
    for f in result.findings:
        pkg_name = f.package.split("@")[0] if "@" in f.package else f.package
        # Handle scoped packages in findings (e.g., @scope/name@version)
        if "/" in pkg_name and pkg_name.startswith("@"):
            pkg_name = pkg_name.rsplit("@", 1)[0] if "@" in pkg_name[1:] else pkg_name

        vuln_id = hashlib.sha256(f"{f.rule_id}:{f.package}:{f.file}".encode()).hexdigest()[:16]

        if (vuln_id, pkg_name) in seen_vulns:
            continue
        seen_vulns.add((vuln_id, pkg_name))

        vuln = {
            "bom-ref": vuln_id,
            "id": f"PICOSENTRY-{result.scan_id[:8]}-{vuln_id[:8]}",
            "source": {"name": "PicoSentry", "url": "https://github.com/KirkForge/PicoSentry"},
            "ratings": [
                {
                    "severity": _SEVERITY_RATING.get(f.severity, "info"),
                    "method": "other",
                    "score": _CONFIDENCE_SCORE.get(f.confidence.value, 0.5),
                }
            ],
            "description": f.message,
            "detail": f.evidence,
            "recommendation": f.remediation,
        }
        # Link to component if it exists in the inventory
        if pkg_name in comp_refs:
            vuln["affects"] = [{"ref": comp_refs[pkg_name]}]
        else:
            vuln["affects"] = []

        if f.references:
            vuln["advisories"] = [{"url": ref} for ref in f.references]
        vulns.append(vuln)

    # Root component
    root_name = result.target.rsplit("/", 1)[-1] if "/" in result.target else result.target

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{result.scan_id}",
        "version": 1,
        "metadata": {
            "timestamp": det_timestamp,
            "tools": [
                {
                    "vendor": "KirkForge",
                    "name": "PicoSentry",
                    "version": result.engine_version,
                }
            ],
            "component": {
                "type": "application",
                "name": root_name,
                "bom-ref": hashlib.sha256(result.target.encode()).hexdigest()[:16],
            },
        },
        "components": components,
        "vulnerabilities": vulns,
    }

    return json.dumps(bom, sort_keys=True, indent=2)
