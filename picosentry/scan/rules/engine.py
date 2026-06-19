from __future__ import annotations

from pathlib import Path

from ..models import Confidence, Finding, Severity
from .utils import iter_node_modules, load_package_json

__all__ = ["detect_engine_issues"]

OVERLY_PERMISSIVE = ("*", "", ">=0.0.0", "x", "any", "latest", "*.*.*")


def _is_overly_permissive(version_str: str) -> bool:
    stripped = version_str.strip()
    if stripped in OVERLY_PERMISSIVE:
        return True

    if stripped.startswith(">="):
        base = stripped[2:].strip()
        parts = base.split(".")
        if all(p == "0" for p in parts if p.isdigit()):
            return True
    return False


def _is_exact_version(version_str: str) -> bool:
    stripped = version_str.strip()

    return bool(
        stripped and stripped[0].isdigit() and not any(c in stripped for c in ("*", "^", "~", ">", "<", "|", " "))
    )


def _check_engines(pkg: dict, pkg_json_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    pkg_name = pkg.get("name", pkg_json_path.parent.name)
    pkg_version = pkg.get("version", "unknown")
    pkg_label = f"{pkg_name}@{pkg_version}"

    engines = pkg.get("engines")

    if engines is None or engines == {}:
        scripts = pkg.get("scripts", {})
        has_install_script = isinstance(scripts, dict) and any(
            k in scripts for k in ("install", "postinstall", "preinstall")
        )
        if has_install_script:
            findings.append(
                Finding(
                    rule_id="L2-ENGIN-001",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    package=pkg_label,
                    file=str(pkg_json_path),
                    message=(
                        f"Package '{pkg_name}' has install scripts but no engines constraint — "
                        "runs on any Node version including potentially compromised environments"
                    ),
                    evidence="engines field missing, scripts.install/postinstall/preinstall present",
                    remediation=(
                        "Add an 'engines' field specifying supported Node.js versions. "
                        "Install scripts without engine constraints can execute on any runtime."
                    ),
                    references=[
                        "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#engines",
                    ],
                )
            )
        else:
            findings.append(
                Finding(
                    rule_id="L2-ENGIN-001",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    package=pkg_label,
                    file=str(pkg_json_path),
                    message=f"Package '{pkg_name}' has no engines field — compatibility is untested",
                    evidence="engines field missing",
                    remediation=(
                        "Add an 'engines' field to declare supported Node.js versions. "
                        "This helps consumers know if the package is compatible."
                    ),
                    references=[
                        "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#engines",
                    ],
                )
            )
        return findings

    if not isinstance(engines, dict):
        return findings

    node_version = engines.get("node")
    if node_version is not None:
        if _is_overly_permissive(str(node_version)):
            findings.append(
                Finding(
                    rule_id="L2-ENGIN-001",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.EXACT,
                    package=pkg_label,
                    file=str(pkg_json_path),
                    message=(
                        f"Package '{pkg_name}' has overly permissive Node.js engine constraint: "
                        f"'{node_version}' — effectively no version restriction"
                    ),
                    evidence=f"engines.node = {node_version!r}",
                    remediation=(
                        "Specify a meaningful Node.js version range, e.g., '>=18.0.0'. "
                        "Overly permissive constraints provide no compatibility guarantee."
                    ),
                    references=[
                        "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#engines",
                    ],
                )
            )
        elif _is_exact_version(str(node_version)):
            findings.append(
                Finding(
                    rule_id="L2-ENGIN-001",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    package=pkg_label,
                    file=str(pkg_json_path),
                    message=(
                        f"Package '{pkg_name}' pins to exact Node.js version: "
                        f"'{node_version}' — may fail on other Node versions"
                    ),
                    evidence=f"engines.node = {node_version!r} (exact pin)",
                    remediation=(
                        "Consider using a range like '>=18.0.0 <21.0.0' instead of an exact version. "
                        "Exact pins can cause compatibility issues for consumers."
                    ),
                    references=[
                        "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#engines",
                    ],
                )
            )

    if "npm" in engines and "node" not in engines:
        findings.append(
            Finding(
                rule_id="L2-ENGIN-001",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                package=pkg_label,
                file=str(pkg_json_path),
                message=f"Package '{pkg_name}' specifies npm engine but not node — incomplete constraint",
                evidence=f"engines = {engines} (npm without node)",
                remediation=(
                    "Add a 'node' engine constraint alongside 'npm'. "
                    "Node.js version is more impactful for compatibility than npm version."
                ),
                references=[
                    "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#engines",
                ],
            )
        )

    return findings


def detect_engine_issues(target: Path) -> list[Finding]:
    findings: list[Finding] = []

    root_pkg = target / "package.json"
    if root_pkg.is_file():
        pkg = load_package_json(root_pkg)
        if pkg:
            findings.extend(_check_engines(pkg, root_pkg))

    for pkg_json, pkg in iter_node_modules(target):
        findings.extend(_check_engines(pkg, pkg_json))

    return findings
