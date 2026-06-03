"""
L2-BUND-001: Bundled dependency shadow detection.

Flags packages that bundle their own copies of dependencies inside
dist tarballs (via "bundledDependencies" or "files" field), which can
hide malicious or outdated code from audit tools.

Pure function: (target_path, corpus_dir) → List[Finding]
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .utils import iter_node_modules, load_package_json

__all__ = ["detect_bundled_shadows"]


def _check_bundled(pkg: dict, pkg_json: Path) -> list[Finding]:
    """Check a single package.json for bundled dependency issues."""
    findings: list[Finding] = []
    pkg_name = pkg.get("name", pkg_json.parent.name)
    pkg_version = pkg.get("version", "unknown")
    pkg_label = f"{pkg_name}@{pkg_version}"

    # L2-BUND-001: bundledDependencies / bundleDependencies
    bundled = pkg.get("bundledDependencies") or pkg.get("bundleDependencies")
    if bundled:
        if isinstance(bundled, list):
            findings.append(
                Finding(
                    rule_id="L2-BUND-001",
                    severity=Severity.HIGH,
                    confidence=Confidence.EXACT,
                    package=pkg_label,
                    file=str(pkg_json),
                    message=(
                        f"Package declares {len(bundled)} bundled dependencies — "
                        "these are not auditable by standard npm audit"
                    ),
                    evidence=f"bundledDependencies: {bundled[:20]}",
                    remediation=(
                        "Bundled dependencies bypass npm audit and may contain "
                        "outdated or malicious code. Consider using --ignore-scripts "
                        "and auditing the package's source repository manually."
                    ),
                    references=[
                        "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#bundledependencies",
                        "https://blog.npmjs.org/post/171139955325/bundled-dependencies",
                    ],
                )
            )
        elif isinstance(bundled, bool) and bundled:
            findings.append(
                Finding(
                    rule_id="L2-BUND-001",
                    severity=Severity.HIGH,
                    confidence=Confidence.EXACT,
                    package=pkg_label,
                    file=str(pkg_json),
                    message=(
                        "Package declares bundledDependencies=true — all dependencies are bundled and not auditable"
                    ),
                    evidence="bundledDependencies: true",
                    remediation=(
                        "Bundled dependencies bypass npm audit. Audit the package's source repository manually."
                    ),
                    references=[
                        "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#bundledependencies",
                    ],
                )
            )

    # Check "files" field for suspicious inclusions
    files_field = pkg.get("files")
    if isinstance(files_field, list):
        # Flag if "files" includes node_modules or dist with compiled code
        suspicious = [f for f in files_field if f in ("node_modules", "dist", "build", "out")]
        if suspicious:
            findings.append(
                Finding(
                    rule_id="L2-BUND-001",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    package=pkg_label,
                    file=str(pkg_json),
                    message=(
                        f"Package 'files' field includes: {', '.join(suspicious)} — "
                        "may bundle compiled code that bypasses audit"
                    ),
                    evidence=f"files: {files_field[:20]}",
                    remediation=(
                        "Review the published tarball contents. "
                        "'files' entries like 'dist' or 'node_modules' may contain "
                        "pre-compiled or bundled code not visible to npm audit."
                    ),
                    references=[
                        "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#files",
                    ],
                )
            )

    # Check for packages that ship pre-built native binaries
    binary_field = pkg.get("binary")
    if binary_field and isinstance(binary_field, dict):
        findings.append(
            Finding(
                rule_id="L2-BUND-001",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                package=pkg_label,
                file=str(pkg_json),
                message=("Package declares pre-built binary configuration — native binaries bypass source audit"),
                evidence=f"binary: {json.dumps(binary_field)[:200]}",
                remediation=(
                    "Pre-built binaries cannot be audited for security. "
                    "Verify the binary source and build from source if possible."
                ),
                references=[
                    "https://github.com/prebuild/prebuild",
                    "https://nodejs.org/api/n-api.html",
                ],
            )
        )

    return findings


def detect_bundled_shadows(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect bundled dependency shadows — packages that bundle their own deps,
    hiding them from audit tools.
    No network calls. Pure filesystem scan.
    """
    findings: list[Finding] = []

    # Root package.json
    root_pkg = target / "package.json"
    if root_pkg.is_file():
        pkg = load_package_json(root_pkg)
        if pkg:
            findings.extend(_check_bundled(pkg, root_pkg))

    # node_modules packages
    for pkg_json, pkg in iter_node_modules(target):
        findings.extend(_check_bundled(pkg, pkg_json))

    return findings
