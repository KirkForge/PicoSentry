"""
L2-PROV-001: Provenance attestation detection.

Flags packages that lack provenance attestations or signature verification.
Provenance links a package to its source code build, making supply chain
attacks harder. Packages without provenance are harder to trust.

Pure function: (target_path, corpus_dir) → List[Finding]
"""

from __future__ import annotations

from pathlib import Path

from ..models import Confidence, Finding, Severity
from .utils import iter_node_modules, load_package_json

__all__ = ["detect_provenance_issues"]
# SLSA provenance fields in npm package.json
PROVENANCE_FIELDS = (
    "provenance",
    "attestations",
    "_integrity",
    "_shasum",
    "_signatures",
)

# Integrity algorithms considered modern
MODERN_INTEGRITY = ("sha512-", "sha384-", "sha256-")

# Deprecated or weak integrity
WEAK_INTEGRITY = ("sha1-", "md5-")


def _check_provenance(pkg: dict, pkg_json: Path) -> list[Finding]:
    """Check a single package for provenance issues."""
    findings: list[Finding] = []
    pkg_name = pkg.get("name", pkg_json.parent.name)
    pkg_version = pkg.get("version", "unknown")
    pkg_label = f"{pkg_name}@{pkg_version}"

    has_provenance = False
    for field in PROVENANCE_FIELDS:
        if pkg.get(field):
            has_provenance = True
            break

    # Check repository field — packages without it can't have provenance
    repo = pkg.get("repository")
    if not repo:
        findings.append(
            Finding(
                rule_id="L2-PROV-001",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                package=pkg_label,
                file=str(pkg_json),
                message=f"Package '{pkg_name}' has no repository field — provenance cannot be verified",
                evidence="repository field missing",
                remediation=(
                    "Packages without a repository URL cannot be verified for provenance. "
                    "Check the npm registry page for source information."
                ),
                references=[
                    "https://docs.npmjs.com/generating-provenance-statements",
                ],
            )
        )
    elif isinstance(repo, str) and "github.com" not in repo.lower():
        # Simple string repo — can extract URL
        findings.append(
            Finding(
                rule_id="L2-PROV-001",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                package=pkg_label,
                file=str(pkg_json),
                message=(
                    f"Package '{pkg_name}' repository is not on GitHub — npm provenance attestation is not available"
                ),
                evidence=f"repository: {repo}",
                remediation=(
                    "npm provenance attestation currently requires GitHub Actions. "
                    "Packages hosted elsewhere cannot provide SLSA provenance."
                ),
                references=[
                    "https://docs.npmjs.com/generating-provenance-statements",
                ],
            )
        )

    # Check for integrity in node_modules/.package-lock.json
    # This is handled by lockfile_drift, but we can check package-level integrity

    # Check if package has _integrity with weak algorithm
    integrity = pkg.get("_integrity", "")
    if integrity and isinstance(integrity, str) and any(integrity.startswith(algo) for algo in WEAK_INTEGRITY):
        findings.append(
            Finding(
                rule_id="L2-PROV-001",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                package=pkg_label,
                file=str(pkg_json),
                message=(f"Package '{pkg_name}' uses weak integrity algorithm — vulnerable to collision attacks"),
                evidence=f"_integrity: {integrity[:60]}",
                remediation=(
                    "Use sha512-based integrity hashes. Weak algorithms like sha1 are vulnerable to collision attacks."
                ),
                references=[
                    "https://docs.npmjs.com/cli/v10/commands/npm-install#integrity",
                    "https://shattered.io/",
                ],
            )
        )

    # Check for missing _integrity entirely (in installed packages)
    # This indicates the package may have been installed without verification
    # Only flag in node_modules context (not root package.json)
    if not integrity and not pkg.get("_shasum") and "node_modules" in pkg_json.parts:
        findings.append(
            Finding(
                rule_id="L2-PROV-001",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                package=pkg_label,
                file=str(pkg_json),
                message=(f"Package '{pkg_name}' has no integrity hash — contents cannot be verified against registry"),
                evidence="no _integrity or _shasum field",
                remediation=(
                    "Run 'npm install --ignore-scripts' to regenerate integrity hashes. "
                    "Missing hashes mean package contents cannot be verified."
                ),
                references=[
                    "https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json#integrity",
                ],
            )
        )

    # Flag packages without provenance that are in production dependencies
    if not has_provenance and "node_modules" in pkg_json.parts:
        # Check if it's a direct dependency (not just transitive)
        # We flag all as LOW — provenance is a new standard
        findings.append(
            Finding(
                rule_id="L2-PROV-001",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                package=pkg_label,
                file=str(pkg_json),
                message=(
                    f"Package '{pkg_name}' lacks provenance attestation — "
                    "cannot verify it was built from the claimed source"
                ),
                evidence="no provenance/attestations field in package.json",
                remediation=(
                    "Prefer packages with npm provenance attestations. "
                    "Check if the package publishes provenance on npmjs.com."
                ),
                references=[
                    "https://docs.npmjs.com/generating-provenance-statements",
                    "https://slsa.dev/spec/v1.0/provenance",
                ],
            )
        )

    return findings


def detect_provenance_issues(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect provenance attestation issues — packages lacking source verification.
    No network calls. Pure filesystem scan.
    """
    findings: list[Finding] = []

    # Root package.json
    root_pkg = target / "package.json"
    if root_pkg.is_file():
        pkg = load_package_json(root_pkg)
        if pkg:
            findings.extend(_check_provenance(pkg, root_pkg))

    # node_modules packages
    for pkg_json, pkg in iter_node_modules(target):
        findings.extend(_check_provenance(pkg, pkg_json))

    return findings
