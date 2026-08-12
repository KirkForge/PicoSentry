from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..models import Confidence, Finding, Severity
from .utils import iter_node_modules, load_package_json

if TYPE_CHECKING:
    from ..package_intel import PackageIntel

__all__ = ["detect_suspicious_new_packages"]

# A package with fewer than this many downloads in the last month AND younger
# than this many days is treated as suspiciously new. Thresholds are the
# workorder's spec (download_count < 100 AND age < 30 days) — do not lower.
LOW_DOWNLOAD_THRESHOLD = 100
YOUNG_AGE_THRESHOLD_DAYS = 30


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
    if intel.download_count >= LOW_DOWNLOAD_THRESHOLD:
        return
    if intel.package_age_days >= YOUNG_AGE_THRESHOLD_DAYS:
        return

    pkg_name = pkg.get("name", pkg_json.parent.name)
    pkg_version = pkg.get("version", "unknown")
    findings.append(
        Finding(
            rule_id="L2-INTEL-001",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            package=f"{pkg_name}@{pkg_version}",
            file=str(pkg_json),
            message=(
                f"Package '{pkg_name}' is suspiciously new: "
                f"{intel.download_count} downloads in the last month, "
                f"{intel.package_age_days} days old"
            ),
            evidence=(f"download_count={intel.download_count}, package_age_days={intel.package_age_days}"),
            remediation=(
                "Very young packages with almost no downloads are a common "
                "typosquat/supply-chain vector. Verify the package source, "
                "publisher identity, and repository before adopting it."
            ),
            references=[
                "https://docs.npmjs.com/cli/v10/using-npm/package-specification-npm",
            ],
        )
    )


def detect_suspicious_new_packages(target: Path, package_intel: dict[str, PackageIntel] | None = None) -> list[Finding]:
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
