
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from picosentry.scan.models import ScanResult, Severity
from picosentry.scan.rules.utils import load_package_json


_ECOSYSTEM_PURL_PREFIXES = {
    "npm": "pkg:npm",
    "pypi": "pkg:pypi",
    "go": "pkg:golang",
    "cargo": "pkg:cargo",
    "maven": "pkg:maven",
    "rubygems": "pkg:gem",
    "nuget": "pkg:nuget",
}

_PURL_PREFIX = "pkg:npm"  # default for backward compatibility


def _walk_node_modules(target: Path) -> list[dict]:
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

                    if "dist" in pkg and isinstance(pkg["dist"], dict):
                        shasum = pkg["dist"].get("shasum", "")
                        integrity = pkg["dist"].get("integrity", "")
                        if integrity:
                            algo, _, hash_val = integrity.partition("-")
                            comp["hashes"] = [{"alg": algo.upper(), "content": hash_val}]
                        elif shasum:
                            comp["hashes"] = [{"alg": "SHA-1", "content": shasum}]
                    components[key] = comp


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


    _sid = result.scan_id  # sha256-based, 16 hex chars
    det_timestamp = f"20{_sid[:2]}-{_sid[2:4]}-{_sid[4:6]}T{_sid[6:8]}:{_sid[8:10]}:{_sid[10:12]}Z"


    target_path = Path(result.target)
    components = _walk_node_modules(target_path)


    comp_refs: dict[str, str] = {c["name"]: c["bom-ref"] for c in components}


    vulns: list[dict] = []
    seen_vulns: set[tuple] = set()
    for f in result.findings:
        pkg_name = f.package.split("@")[0] if "@" in f.package else f.package

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

        if pkg_name in comp_refs:
            vuln["affects"] = [{"ref": comp_refs[pkg_name]}]
        else:
            vuln["affects"] = []

        if f.references:
            vuln["advisories"] = [{"url": ref} for ref in f.references]
        vulns.append(vuln)


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
