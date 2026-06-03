"""
L2-MANI-001: Manifest integrity — version range attacks.
L2-MANI-002: Optional dependencies with install scripts.

Flags dangerous version ranges (>=0.0.0, *, empty), and optional
dependencies that declare install scripts (supply chain attack vector).

Pure function: (target_path, corpus_dir) → List[Finding]
"""

from __future__ import annotations

from pathlib import Path

from ..models import Confidence, Finding, Severity
from .utils import iter_node_modules, load_package_json

__all__ = ["detect_manifest_issues"]
# Version ranges that accept ANY version — supply chain attack enablers.
DANGEROUS_RANGES = ("*", "", ">=", ">=0.0.0", "x", "latest", "*.*.*")

# Install-time script keys that execute code.
INSTALL_SCRIPT_KEYS = ("install", "postinstall", "preinstall", "prepare", "prepack")


def _get_dep_sections(pkg: dict) -> dict[str, dict]:
    """Return {section_name: {pkg: version_str}} for all dependency sections."""
    sections: dict[str, dict] = {}
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        section = pkg.get(key)
        if isinstance(section, dict):
            sections[key] = section
    return sections


def _is_dangerous_range(version_str: str) -> bool:
    """Check if a version range is overly permissive."""
    if not isinstance(version_str, str):
        return False
    stripped = version_str.strip()
    # Exact matches
    if stripped in DANGEROUS_RANGES:
        return True
    # Prefixes like ">=0.0.0", "^*", "~*"
    for prefix in (">=", "^", "~", ">"):
        for dangerous in ("*", "0.0.0"):
            if stripped == f"{prefix}{dangerous}":
                return True
    # ">=0" with no upper bound
    if stripped.startswith(">=") and stripped.replace(">=", "").strip().replace(".", "0").isdigit():
        base = stripped[2:].strip()
        parts = base.split(".")
        if all(p == "0" for p in parts):
            return True
    return False


def _check_manifest(pkg: dict, pkg_json_path: Path) -> list[Finding]:
    """Check a single package.json for manifest issues."""
    findings: list[Finding] = []
    pkg_name = pkg.get("name", pkg_json_path.parent.name)
    pkg_version = pkg.get("version", "unknown")
    pkg_label = f"{pkg_name}@{pkg_version}"

    sections = _get_dep_sections(pkg)

    # L2-MANI-001: Dangerous version ranges
    for section_name, deps in sections.items():
        for dep_name, version_str in sorted(deps.items()):
            if _is_dangerous_range(str(version_str)):
                findings.append(
                    Finding(
                        rule_id="L2-MANI-001",
                        severity=Severity.HIGH,
                        confidence=Confidence.EXACT,
                        package=pkg_label,
                        file=str(pkg_json_path),
                        message=(
                            f"Dependency '{dep_name}' uses overly permissive "
                            f"version range '{version_str}' in {section_name}"
                        ),
                        evidence=f"{section_name}.{dep_name} = {version_str!r}",
                        remediation=(
                            f"Pin '{dep_name}' to an exact version or narrow range. "
                            "Overly permissive ranges allow malicious updates."
                        ),
                        references=[
                            "https://docs.npmjs.com/cli/v10/using-npm/specifiers",
                            "https://blog.npmjs.org/post/162780572570/how-to-avoid-npm-version-range-typos",
                        ],
                    )
                )

    # L2-MANI-002: Optional dependencies with install scripts
    # Consolidate into a single finding per package (was one per optional dep — noisy)
    optional_deps = pkg.get("optionalDependencies", {})
    if isinstance(optional_deps, dict) and optional_deps:
        scripts = pkg.get("scripts", {})
        if isinstance(scripts, dict):
            has_install_script = any(k in scripts for k in INSTALL_SCRIPT_KEYS)
            if has_install_script:
                dep_names = sorted(optional_deps.keys())
                script_keys_found = [k for k in INSTALL_SCRIPT_KEYS if k in scripts]
                findings.append(
                    Finding(
                        rule_id="L2-MANI-002",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        package=pkg_label,
                        file=str(pkg_json_path),
                        message=(
                            f"{len(dep_names)} optional dependenc{'y' if len(dep_names) == 1 else 'ies'} "
                            f"declared alongside install scripts — "
                            f"optional deps may silently install malicious code"
                        ),
                        evidence=(
                            f"optionalDependencies: {', '.join(dep_names)} + scripts: {', '.join(script_keys_found)}"
                        ),
                        remediation=(
                            "Move optional dependencies to peerDependencies or devDependencies. "
                            "Use --ignore-optional to skip them during install."
                        ),
                        references=[
                            "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#optionaldependencies",
                        ],
                    )
                )

    return findings


def detect_manifest_issues(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect manifest integrity issues — dangerous version ranges and
    optional deps with install scripts.
    No network calls. Pure filesystem scan.
    """
    findings: list[Finding] = []

    # Root package.json
    root_pkg = target / "package.json"
    if root_pkg.is_file():
        pkg = load_package_json(root_pkg)
        if pkg:
            findings.extend(_check_manifest(pkg, root_pkg))

    # node_modules packages
    for pkg_json, pkg in iter_node_modules(target):
        findings.extend(_check_manifest(pkg, pkg_json))

    return findings
