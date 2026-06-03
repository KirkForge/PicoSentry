"""
L2-LICENSE-001: License compliance and missing license detection.

Flags packages with:
- No license field (supply chain risk — legal unknown)
- "UNLICENSED" license (proprietary, no redistribution rights)
- Copyleft licenses (GPL, AGPL) in dependency chain (infectious for proprietary projects)
- Custom/unknown license strings that don't match SPDX identifiers

Pure function: (target_path, corpus_dir) → List[Finding]
"""

from __future__ import annotations

from pathlib import Path

from ..models import Confidence, Finding, Severity
from .utils import iter_node_modules, load_package_json

__all__ = ["detect_license_issues"]
# SPDX license identifiers that are copyleft (viral for proprietary code)
COPYLEFT_LICENSES = frozenset(
    {
        "GPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "AGPL-1.0",
        "AGPL-1.0-only",
        "AGPL-1.0-or-later",
        "AGPL-3.0",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "LGPL-2.0",
        "LGPL-2.0-only",
        "LGPL-2.0-or-later",
        "LGPL-2.1",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "GPL-1.0",
        "OSL-3.0",
        "CPAL-1.0",
        "EUPL-1.1",
        "EUPL-1.2",
        "MPL-2.0",  # weak copyleft but still has requirements
    }
)

# Common permissive licenses (safe for most projects)
PERMISSIVE_LICENSES = frozenset(
    {
        "MIT",
        "MIT License",
        "Apache-2.0",
        "Apache License 2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "0BSD",
        "Unlicense",
        "CC0-1.0",
        "WTFPL",
        "Zlib",
        "PSF-2.0",
        "Python-2.0",
    }
)

# Dual-license patterns
DUAL_LICENSE_PREFIXES = ("(MIT OR Apache-2.0)", "(MIT AND Apache-2.0)")


def _check_license_value(license_value: str) -> tuple:
    """
    Classify a license string.

    Returns: (is_copyleft, is_permissive, is_unlicensed, is_unknown)
    """
    if not license_value or not isinstance(license_value, str):
        return False, False, False, True

    lic = license_value.strip()

    if lic.upper() == "UNLICENSED" or lic == "SEE LICENSE IN LICENSE":
        return False, False, True, False

    # Check for copyleft
    for copyleft in COPYLEFT_LICENSES:
        if copyleft.lower() in lic.lower():
            return True, False, False, False

    # Check for dual-license with copyleft
    if "GPL" in lic.upper() or "AGPL" in lic.upper():
        return True, False, False, False

    # Check for permissive
    for permissive in PERMISSIVE_LICENSES:
        if permissive.lower() == lic.lower():
            return False, True, False, False

    # Check common permissive patterns
    lic_lower = lic.lower()
    if any(p in lic_lower for p in ("mit", "bsd", "apache", "isc", "0bsd")):
        return False, True, False, False

    # Dual license patterns
    if lic.startswith("(MIT OR Apache-2.0)"):
        return False, True, False, False

    # If it contains "OR" it might be a dual license — assume permissive if MIT/Apache involved
    if " OR " in lic and ("MIT" in lic or "Apache" in lic):
        return False, True, False, False

    return False, False, False, True


def _scan_package_json(pkg_json: Path) -> list[Finding]:
    """Scan a single package.json for license issues."""
    findings: list[Finding] = []
    data = load_package_json(pkg_json)
    if not data:
        return findings

    pkg_name = data.get("name", pkg_json.parent.name)
    pkg_version = data.get("version", "unknown")
    pkg_label = f"{pkg_name}@{pkg_version}"

    # Check license field
    # npm supports: "license": "MIT" or "license": {"type": "MIT", "url": "..."}
    license_field = data.get("license")

    if license_field is None:
        findings.append(
            Finding(
                rule_id="L2-LICENSE-001",
                severity=Severity.MEDIUM,
                confidence=Confidence.EXACT,
                package=pkg_label,
                file=str(pkg_json),
                message=f"Package {pkg_label} has no license field — legal status unknown",
                evidence="license field missing from package.json",
                remediation=(
                    f"Contact the {pkg_name} maintainer to add a license. "
                    "Packages without a license cannot be legally used in most projects."
                ),
                references=[
                    "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#license",
                    "https://spdx.org/licenses/",
                ],
            )
        )
        return findings

    if isinstance(license_field, dict):
        license_value = license_field.get("type", "")
    elif isinstance(license_field, str):
        license_value = license_field
    else:
        license_value = str(license_field)

    is_copyleft, is_permissive, is_unlicensed, is_unknown = _check_license_value(license_value)

    if is_unlicensed:
        findings.append(
            Finding(
                rule_id="L2-LICENSE-001",
                severity=Severity.HIGH,
                confidence=Confidence.EXACT,
                package=pkg_label,
                file=str(pkg_json),
                message=f"Package {pkg_label} is explicitly UNLICENSED — no redistribution rights",
                evidence=f"license = {license_value!r}",
                remediation=(
                    f"Remove {pkg_name} from dependencies if your project is proprietary. "
                    "UNLICENSED means the author has not granted any license to use, modify, or distribute."
                ),
                references=[
                    "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#license",
                ],
            )
        )
    elif is_copyleft:
        findings.append(
            Finding(
                rule_id="L2-LICENSE-001",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                package=pkg_label,
                file=str(pkg_json),
                message=f"Package {pkg_label} uses copyleft license: {license_value}",
                evidence=f"license = {license_value!r}",
                remediation=(
                    f"Review if {pkg_name}'s copyleft license is compatible with your project. "
                    "GPL/AGPL requires derivative works to also be open source. "
                    "Consider finding a permissively-licensed alternative."
                ),
                references=[
                    "https://www.gnu.org/licenses/gpl-faq.html",
                    "https://spdx.org/licenses/",
                ],
            )
        )
    elif is_unknown:
        findings.append(
            Finding(
                rule_id="L2-LICENSE-001",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                package=pkg_label,
                file=str(pkg_json),
                message=f"Package {pkg_label} has unrecognized license: {license_value}",
                evidence=f"license = {license_value!r}",
                remediation=(
                    f"Verify the license for {pkg_name} manually. "
                    f"The value {license_value!r} is not a recognized SPDX identifier."
                ),
                references=[
                    "https://spdx.org/licenses/",
                ],
            )
        )

    return findings


def detect_license_issues(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect packages with missing, unlicensed, or copyleft licenses.

    No network calls. Pure filesystem scan.
    """
    findings: list[Finding] = []

    # Root package.json
    root_pkg = target / "package.json"
    if root_pkg.is_file():
        findings.extend(_scan_package_json(root_pkg))

    # node_modules packages
    for pkg_json, _pkg in iter_node_modules(target):
        findings.extend(_scan_package_json(pkg_json))

    return findings
