from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..models import Confidence, Finding, Severity
from .utils import iter_node_modules, load_package_json

if TYPE_CHECKING:
    from ..package_intel import PackageIntel

__all__ = ["detect_version_confusion"]

# A package is "popular" if it has at least this many downloads in the last
# month, and "established" if it has been published for at least this many
# days. A squat on a popular, established package is the attack; a brand-new
# or low-download package at 1.0.0 is a normal first release. Thresholds are
# the workorder's spec — do not lower.
POPULAR_DOWNLOAD_THRESHOLD = 1000
ESTABLISHED_AGE_THRESHOLD_DAYS = 30

# Declared versions that are classic squat markers: a package that has been
# around for months with real adoption should not still be pinned at these.
SQUAT_VERSIONS = frozenset({"0.0.0", "1.0.0"})


def _check_package(
    pkg: dict,
    pkg_json: Path,
    findings: list[Finding],
    intel: PackageIntel | None,
) -> None:
    if intel is None:
        return
    if intel.download_count is None or intel.package_age_days is None:
        return  # no registry intel (offline) — nothing to flag
    if intel.download_count < POPULAR_DOWNLOAD_THRESHOLD:
        return
    if intel.package_age_days < ESTABLISHED_AGE_THRESHOLD_DAYS:
        return

    declared = str(pkg.get("version", "")).strip()
    if declared not in SQUAT_VERSIONS:
        return

    pkg_name = pkg.get("name", pkg_json.parent.name)
    findings.append(
        Finding(
            rule_id="L2-VCONF-001",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            package=f"{pkg_name}@{declared}",
            file=str(pkg_json),
            message=(
                f"Package '{pkg_name}' declares version '{declared}' but is a "
                f"popular, established package ({intel.download_count} downloads "
                f"in the last month, {intel.package_age_days} days old) — possible "
                "version-squatting"
            ),
            evidence=(
                f"declared_version={declared}, download_count={intel.download_count}, "
                f"package_age_days={intel.package_age_days}"
            ),
            remediation=(
                "A popular, established package should not be pinned at a "
                "placeholder version like 0.0.0 or 1.0.0. Verify the package "
                "source and publisher, and pin to the real published version."
            ),
            references=[
                "https://docs.npmjs.com/cli/v10/using-npm/package-specification-npm",
            ],
        )
    )


def detect_version_confusion(target: Path, package_intel: dict[str, PackageIntel] | None = None) -> list[Finding]:
    findings: list[Finding] = []

    root_pkg = target / "package.json"
    if root_pkg.is_file():
        pkg = load_package_json(root_pkg)
        if pkg:
            pkg_name = pkg.get("name", "")
            intel = package_intel.get(pkg_name) if package_intel and pkg_name else None
            _check_package(pkg, root_pkg, findings, intel)

    for pkg_json, pkg in iter_node_modules(target):
        pkg_name = pkg.get("name", "")
        intel = package_intel.get(pkg_name) if package_intel and pkg_name else None
        _check_package(pkg, pkg_json, findings, intel)

    return findings
