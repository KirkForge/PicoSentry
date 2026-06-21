from __future__ import annotations

from pathlib import Path

from ..models import Confidence, Finding, Severity
from .utils import iter_node_modules, load_package_json

__all__ = ["detect_provenance_issues"]

PROVENANCE_FIELDS = (
    "provenance",
    "attestations",
    "_integrity",
    "_shasum",
    "_signatures",
)


MODERN_INTEGRITY = ("sha512-", "sha384-", "sha256-")


WEAK_INTEGRITY = ("sha1-", "md5-")


def _check_provenance(pkg: dict, pkg_json: Path) -> list[Finding]:
    findings: list[Finding] = []
    pkg_name = pkg.get("name", pkg_json.parent.name)
    pkg_version = pkg.get("version", "unknown")
    pkg_label = f"{pkg_name}@{pkg_version}"

    has_provenance = False
    for field in PROVENANCE_FIELDS:
        if pkg.get(field):
            has_provenance = True
            break

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

    if not has_provenance and "node_modules" in pkg_json.parts:
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


def detect_provenance_issues(target: Path) -> list[Finding]:
    findings: list[Finding] = []

    root_pkg = target / "package.json"
    if root_pkg.is_file():
        pkg = load_package_json(root_pkg)
        if pkg:
            findings.extend(_check_provenance(pkg, root_pkg))

    for pkg_json, pkg in iter_node_modules(target):
        findings.extend(_check_provenance(pkg, pkg_json))

    return findings
