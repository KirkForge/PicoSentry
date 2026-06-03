"""
L2-MAINT-001: Maintainer change detection.

Flags packages where the publisher/maintainer has changed, which is a
key indicator of supply chain attacks (e.g., event-stream@3.3.6 where
the original maintainer handed off to a malicious actor).

Pure function: (target_path, corpus_dir) → List[Finding]

Offline signals detected:
1. _npmUser differs from author — publisher != declared author
2. New maintainers from different domain — org/account transfer signal
3. No author + has install scripts — anonymous RCE risk (event-stream pattern)
4. Single maintainer + install scripts — bus factor + attack surface
5. No author/maintainer at all — unaccountable package
6. Very short author names — pseudonymous publisher risk
"""

from __future__ import annotations

from pathlib import Path

from ..models import Confidence, Finding, Severity
from .utils import iter_node_modules, load_package_json

__all__ = ["detect_maintainer_changes"]


def _extract_author_name(author) -> str:
    """Extract a name string from an author field (string or dict)."""
    if isinstance(author, str):
        # "Name <email>" or "Name (url)" patterns
        name = author.split("<")[0].split("(")[0].strip()
        return name
    elif isinstance(author, dict):
        return str(author.get("name", ""))
    return ""


def _extract_author_names(pkg: dict) -> list[str]:
    """Extract all author/maintainer/contributor names from a package.json."""
    names: list[str] = []

    # Single author field
    author = pkg.get("author")
    if author:
        name = _extract_author_name(author)
        if name:
            names.append(name)

    # Contributors
    for c in pkg.get("contributors", []):
        name = _extract_author_name(c)
        if name:
            names.append(name)

    # Maintainers field (npm-specific)
    for m in pkg.get("maintainers", []):
        name = _extract_author_name(m)
        if name:
            names.append(name)

    return [n for n in names if n]


def _has_install_scripts(pkg: dict) -> bool:
    """Check if a package has lifecycle scripts that execute code."""
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
    """Extract the npm publisher name from _npmUser field."""
    npm_user = pkg.get("_npmUser")
    if isinstance(npm_user, dict):
        return str(npm_user.get("name", ""))
    elif isinstance(npm_user, str):
        return npm_user.split("<")[0].strip()
    return ""


def _extract_maintainer_domains(pkg: dict) -> list[str]:
    """Extract email domains from maintainers list."""
    domains: list[str] = []
    for m in pkg.get("maintainers", []):
        if isinstance(m, dict):
            email = m.get("email", "")
            if "@" in email:
                domains.append(email.rsplit("@", 1)[-1].lower())
        elif isinstance(m, str) and "@" in m:
            domains.append(m.rsplit("@", 1)[-1].strip(">").lower())
    return domains


def _check_maintainer_signals(pkg: dict, pkg_json: Path, findings: list[Finding]) -> None:
    """Check a single package.json for maintainer change signals."""
    pkg_name = pkg.get("name", pkg_json.parent.name)
    pkg_version = pkg.get("version", "unknown")
    pkg_label = f"{pkg_name}@{pkg_version}"
    author_names = _extract_author_names(pkg)
    has_scripts = _has_install_scripts(pkg)

    # --- Signal 1: _npmUser differs from author ---
    # In installed packages, _npmUser shows who published to npm.
    # If it differs from the declared author, someone else published.
    npm_user = _extract_npm_user_name(pkg)
    author_name = _extract_author_name(pkg.get("author", ""))
    if npm_user and author_name:
        # Normalize for comparison
        npm_lower = npm_user.lower().replace("-", "").replace("_", "")
        author_lower = author_name.lower().replace("-", "").replace("_", "")
        if npm_lower != author_lower and npm_lower not in author_lower and author_lower not in npm_lower:
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
                    evidence=f"_npmUser.name={npm_user}, author={author_name}",
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

    # --- Signal 2: Maintainers from different domains ---
    # Original maintainer on @original.com, new one on @suspicious.xyz
    maintainer_domains = _extract_maintainer_domains(pkg)
    if len(maintainer_domains) >= 2 and len(set(maintainer_domains)) >= 2:
        unique_domains = sorted(set(maintainer_domains))
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
                evidence=f"maintainer domains: {', '.join(unique_domains)}",
                remediation=(
                    "Check if the new maintainer domains are expected. "
                    "Unexpected domain changes can indicate account takeover."
                ),
                references=[
                    "https://blog.npmjs.org/post/185010120090/ npm-maintainer-best-practices",
                ],
            )
        )

    # --- Signal 3: No author + has install scripts ---
    # The event-stream pattern: anonymous publisher with code execution.
    if not author_names and has_scripts and pkg_name != "root":
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
                evidence=f"no author field, scripts: {', '.join(s for s in pkg.get('scripts', {}) if s in {'install', 'postinstall', 'preinstall', 'prepare'})}",
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

    # --- Signal 4: Single maintainer + install scripts ---
    # Bus factor: one person controls all execution paths.
    if len(author_names) == 1 and has_scripts:
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
                evidence=f"single maintainer: {author_names[0]}, has install scripts",
                remediation=(
                    "Single-maintainer packages with install scripts pose a bus factor risk. "
                    "If the maintainer's account is compromised, all dependents are affected. "
                    "Consider using --ignore-scripts or auditing the install scripts."
                ),
                references=[],
            )
        )

    # --- Signal 5: No author/maintainer at all ---
    # Already handled by Signal 3 if scripts present; flag without scripts too.
    if not author_names and not has_scripts and pkg_name != "root":
        findings.append(
            Finding(
                rule_id="L2-MAINT-001",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                package=pkg_label,
                file=str(pkg_json),
                message=f"Package '{pkg_name}' has no author or maintainer information",
                evidence="author field missing, maintainers field missing",
                remediation=(
                    "Packages without author information cannot be audited for trust. "
                    "Verify the package source before using."
                ),
                references=[
                    "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#people-fields-author-contributors",
                ],
            )
        )

    # --- Signal 6: Very short author name — pseudonymous risk ---
    if author_names:
        for author in author_names:
            if len(author) <= 2:
                findings.append(
                    Finding(
                        rule_id="L2-MAINT-001",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        package=pkg_label,
                        file=str(pkg_json),
                        message=(f"Package '{pkg_name}' has suspiciously short author name: '{author}'"),
                        evidence=f"author = '{author}'",
                        remediation=(
                            "Very short author names may indicate a pseudonymous publisher. "
                            "Verify the author's identity through npm or GitHub."
                        ),
                        references=[],
                    )
                )


def detect_maintainer_changes(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect packages with maintainer change signals.
    No network calls. Pure filesystem scan.
    """
    findings: list[Finding] = []

    # Check root package.json
    root_pkg = target / "package.json"
    if root_pkg.is_file():
        pkg = load_package_json(root_pkg)
        if pkg:
            _check_maintainer_signals(pkg, root_pkg, findings)

    # Check node_modules packages
    # node_modules packages
    for pkg_json, pkg in iter_node_modules(target):
        _check_maintainer_signals(pkg, pkg_json, findings)

    return findings
