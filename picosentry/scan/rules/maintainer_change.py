from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..models import Confidence, Finding, Severity
from .utils import iter_node_modules, load_package_json

if TYPE_CHECKING:
    from ..package_intel import PackageIntel

__all__ = ["detect_maintainer_changes"]


def _enforce_maintainer_evidence(evidence: str, intel: PackageIntel) -> str:
    parts = [evidence]
    parts.append(f"maintainer_count={intel.maintainer_count}")
    if intel.maintainer_email_domains:
        parts.append(f"domains={', '.join(intel.maintainer_email_domains)}")
    if not intel.has_repository_url:
        parts.append("no repository URL")
    if intel.risk_score > 0:
        parts.append(f"risk_score={intel.risk_score:.2f}")
    return "; ".join(parts)


def _extract_author_name(author) -> str:
    if isinstance(author, str):
        return author.split("<")[0].split("(")[0].strip()
    if isinstance(author, dict):
        return str(author.get("name", ""))
    return ""


def _extract_author_names(pkg: dict) -> list[str]:
    names: list[str] = []

    author = pkg.get("author")
    if author:
        name = _extract_author_name(author)
        if name:
            names.append(name)

    for c in pkg.get("contributors", []):
        name = _extract_author_name(c)
        if name:
            names.append(name)

    for m in pkg.get("maintainers", []):
        name = _extract_author_name(m)
        if name:
            names.append(name)

    return [n for n in names if n]


def _has_install_scripts(pkg: dict) -> bool:
    scripts = pkg.get("scripts", {})
    if not isinstance(scripts, dict):
        return False
    install_scripts = {
        "install",
        "postinstall",
        "preinstall",
        "prepare",
        "prepack",
        "postpack",
    }
    return bool(install_scripts & set(scripts.keys()))


def _extract_npm_user_name(pkg: dict) -> str:
    npm_user = pkg.get("_npmUser")
    if isinstance(npm_user, dict):
        return str(npm_user.get("name", ""))
    if isinstance(npm_user, str):
        return npm_user.split("<")[0].strip()
    return ""


def _extract_maintainer_domains(pkg: dict) -> list[str]:
    domains: list[str] = []
    for m in pkg.get("maintainers", []):
        if isinstance(m, dict):
            email = m.get("email", "")
            if "@" in email:
                domains.append(email.rsplit("@", 1)[-1].lower())
        elif isinstance(m, str) and "@" in m:
            domains.append(m.rsplit("@", 1)[-1].strip(">").lower())
    return domains


def _check_maintainer_signals(
    pkg: dict, pkg_json: Path, findings: list[Finding], pkg_intel: PackageIntel | None = None
) -> None:
    pkg_name = pkg.get("name", pkg_json.parent.name)
    pkg_version = pkg.get("version", "unknown")
    pkg_label = f"{pkg_name}@{pkg_version}"

    if pkg_intel is not None:
        author_count = pkg_intel.maintainer_count
        domains = list(pkg_intel.maintainer_email_domains)
        has_scripts = pkg_intel.has_install_scripts
    else:
        author_count = len(_extract_author_names(pkg))
        domains = _extract_maintainer_domains(pkg)
        has_scripts = _has_install_scripts(pkg)

    author_names = _extract_author_names(pkg)

    npm_user = _extract_npm_user_name(pkg)
    author_name = _extract_author_name(pkg.get("author", ""))
    if npm_user and author_name:
        npm_lower = npm_user.lower().replace("-", "").replace("_", "")
        author_lower = author_name.lower().replace("-", "").replace("_", "")
        if npm_lower != author_lower and npm_lower not in author_lower and author_lower not in npm_lower:
            evidence = f"_npmUser.name={npm_user}, author={author_name}"
            if pkg_intel is not None:
                evidence = _enforce_maintainer_evidence(evidence, pkg_intel)
            findings.append(
                Finding(
                    rule_id="L2-MAINT-001",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    package=pkg_label,
                    file=str(pkg_json),
                    message=(
                        f"Package '{pkg_name}' was published by '{npm_user}' "
                        f"but declares author '{author_name}' — possible maintainer change"
                    ),
                    evidence=evidence,
                    remediation=(
                        "Verify the npm publisher has legitimate access to this package. "
                        "Check npmjs.com for maintainer history and the package's GitHub "
                        "for recent ownership transfers."
                    ),
                    references=[
                        "https://docs.npmjs.com/cli/v10/using-npm/package-specification-npm",
                    ],
                )
            )

    if len(domains) >= 2 and len(set(domains)) >= 2:
        unique_domains = sorted(set(domains))
        evidence = f"maintainer domains: {', '.join(unique_domains)}"
        if pkg_intel is not None:
            evidence = _enforce_maintainer_evidence(evidence, pkg_intel)
        findings.append(
            Finding(
                rule_id="L2-MAINT-001",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                package=pkg_label,
                file=str(pkg_json),
                message=(
                    f"Package '{pkg_name}' has maintainers from {len(unique_domains)} "
                    f"different domains — possible org transfer or account addition"
                ),
                evidence=evidence,
                remediation=(
                    "Check if the new maintainer domains are expected. "
                    "Unexpected domain changes can indicate account takeover."
                ),
                references=[
                    "https://blog.npmjs.org/post/185010120090/ npm-maintainer-best-practices",
                ],
            )
        )

    if author_count == 0 and has_scripts and pkg_name != "root":
        _install_script_names = (
            s for s in pkg.get("scripts", {}) if s in {"install", "postinstall", "preinstall", "prepare"}
        )
        evidence = f"no author field, scripts: {', '.join(sorted(_install_script_names))}"
        if pkg_intel is not None:
            evidence = _enforce_maintainer_evidence(evidence, pkg_intel)
        findings.append(
            Finding(
                rule_id="L2-MAINT-001",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                package=pkg_label,
                file=str(pkg_json),
                message=(
                    f"Package '{pkg_name}' has no author/maintainer info but "
                    f"has install scripts — unaccountable code execution"
                ),
                evidence=evidence,
                remediation=(
                    "Packages without author information that run code on install "
                    "are a critical supply chain risk. Verify the package source, "
                    "check npmjs.com for maintainer history, and consider using "
                    "--ignore-scripts during install."
                ),
                references=[
                    "https://blog.npmjs.org/post/185010120090/npm-maintainer-best-practices",
                ],
            )
        )

    if author_count == 1 and has_scripts:
        single_name = author_names[0] if author_names else "unknown"
        evidence = f"single maintainer: {single_name}, has install scripts"
        if pkg_intel is not None:
            evidence = _enforce_maintainer_evidence(evidence, pkg_intel)
        findings.append(
            Finding(
                rule_id="L2-MAINT-001",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                package=pkg_label,
                file=str(pkg_json),
                message=(
                    f"Package '{pkg_name}' has a single maintainer with install scripts "
                    f"— single point of failure for code execution"
                ),
                evidence=evidence,
                remediation=(
                    "Single-maintainer packages with install scripts pose a bus factor risk. "
                    "If the maintainer's account is compromised, all dependents are affected. "
                    "Consider using --ignore-scripts or auditing the install scripts."
                ),
                references=[],
            )
        )

    if author_count == 0 and not has_scripts and pkg_name != "root":
        evidence = "author field missing, maintainers field missing"
        if pkg_intel is not None:
            evidence = _enforce_maintainer_evidence(evidence, pkg_intel)
        findings.append(
            Finding(
                rule_id="L2-MAINT-001",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                package=pkg_label,
                file=str(pkg_json),
                message=f"Package '{pkg_name}' has no author or maintainer information",
                evidence=evidence,
                remediation=(
                    "Packages without author information cannot be audited for trust. "
                    "Verify the package source before using."
                ),
                references=[
                    "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#people-fields-author-contributors",
                ],
            )
        )

    if author_names:
        for author in author_names:
            if len(author) <= 2:
                evidence = f"author = '{author}'"
                if pkg_intel is not None:
                    evidence = _enforce_maintainer_evidence(evidence, pkg_intel)
                findings.append(
                    Finding(
                        rule_id="L2-MAINT-001",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        package=pkg_label,
                        file=str(pkg_json),
                        message=(f"Package '{pkg_name}' has suspiciously short author name: '{author}'"),
                        evidence=evidence,
                        remediation=(
                            "Very short author names may indicate a pseudonymous publisher. "
                            "Verify the author's identity through npm or GitHub."
                        ),
                        references=[],
                    )
                )


def detect_maintainer_changes(target: Path, package_intel: dict[str, PackageIntel] | None = None) -> list[Finding]:
    findings: list[Finding] = []

    root_pkg = target / "package.json"
    if root_pkg.is_file():
        pkg = load_package_json(root_pkg)
        if pkg:
            pkg_name = pkg.get("name", "")
            intel = package_intel.get(pkg_name) if package_intel and pkg_name else None
            _check_maintainer_signals(pkg, root_pkg, findings, pkg_intel=intel)

    for pkg_json, pkg in iter_node_modules(target):
        pkg_name = pkg.get("name", "")
        intel = package_intel.get(pkg_name) if package_intel and pkg_name else None
        _check_maintainer_signals(pkg, pkg_json, findings, pkg_intel=intel)

    return findings
