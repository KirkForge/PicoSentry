from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..models import Confidence, Finding, Severity
from .utils import iter_node_modules, load_package_json

if TYPE_CHECKING:
    from ..package_intel import PackageIntel

__all__ = ["detect_namespace_collision"]

# A package squatting a well-known scope/namespace must still be new AND
# low-download to fire (keeps FP low on legitimate scoped packages). Same
# thresholds as the workorder spec for the suspicious-new rule — do not lower.
LOW_DOWNLOAD_THRESHOLD = 100
YOUNG_AGE_THRESHOLD_DAYS = 30

# Well-known org/reserved scope prefixes. A package claiming one of these as
# its `@scope` (npm) or namespace prefix (PyPI `google-*`, `aws-*`, ...) is a
# collision risk when it is new and unadopted. Exact prefixes deliberately
# small; unknown scopes are the common case, so any miss is a false negative,
# not a false positive.
SCOPE_PREFIXES = frozenset(
    {
        "@google",
        "@aws",
        "@aws-sdk",
        "@azure",
        "@microsoft",
        "@types",
        "@react",
        "@angular",
        "@vue",
        "@babel",
        "@facebook",
        "@meta",
        "@apple",
        "@sentry",
        "@datadog",
        "@google-cloud",
        "@grpc",
        "@pkg",
    }
)

NAMESPACE_PREFIXES = frozenset(
    {
        "google-",
        "googlecloud",
        "aws-",
        "amazon",
        "azure-",
        "microsoft-",
        "django-",
        "flask-",
        "react-",
        "kubernetes-",
    }
)


def _scope_of(name: str) -> str | None:
    """Return the `@scope` prefix of a scoped name, or None if unscoped."""
    if name.startswith("@") and "/" in name:
        return name.split("/", 1)[0]
    return None


def _collides(name: str) -> str | None:
    scope = _scope_of(name)
    if scope is not None:
        for prefix in SCOPE_PREFIXES:
            if scope.lower() == prefix.lower():
                return prefix
        return None
    lowered = name.lower()
    for prefix in NAMESPACE_PREFIXES:
        if lowered.startswith(prefix.lower()):
            return prefix
    return None


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
    claimed = _collides(pkg_name)
    if claimed is None:
        return

    pkg_version = pkg.get("version", "unknown")
    findings.append(
        Finding(
            rule_id="L2-NSCOL-001",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            package=f"{pkg_name}@{pkg_version}",
            file=str(pkg_json),
            message=(
                f"Package '{pkg_name}' claims well-known namespace/scope '{claimed}' "
                f"but is new ({intel.package_age_days} days) with only "
                f"{intel.download_count} downloads"
            ),
            evidence=(
                f"claimed_namespace={claimed}, download_count={intel.download_count}, "
                f"package_age_days={intel.package_age_days}"
            ),
            remediation=(
                "A brand-new, low-download package squatting a well-known scope or "
                "namespace is a namespace-collision supply-chain vector. Verify the "
                "publisher owns the claimed scope and audit the source before adopting it."
            ),
            references=[
                "https://docs.npmjs.com/cli/v10/using-npm/package-specification-npm",
            ],
        )
    )


def detect_namespace_collision(target: Path, package_intel: dict[str, PackageIntel] | None = None) -> list[Finding]:
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
