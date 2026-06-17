
from __future__ import annotations

import json
import logging
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .pnpm_lock_parser import (
    find_missing_integrity,
    find_weak_integrity,
    parse_pnpm_lockfile,
)
from .utils import load_package_json

__all__ = ["detect_lockfile_drift"]

logger = logging.getLogger("picosentry.lockfile_drift")

WEAK_INTEGRITY = ("sha1-", "md5-")


def _load_lockfile_v1(content: str) -> dict[str, str]:
    deps: dict[str, str] = {}
    try:
        data = json.loads(content)
        for key, entry in data.get("dependencies", {}).items():
            if isinstance(entry, dict) and "version" in entry:


                deps[key] = entry["version"]
    except json.JSONDecodeError:
        pass
    return deps


def _load_lockfile_v2(content: str) -> dict[str, str]:
    deps: dict[str, str] = {}
    try:
        data = json.loads(content)

        for pkg_path, entry in data.get("packages", {}).items():
            if isinstance(entry, dict) and "version" in entry:

                name = entry.get("name", "")
                if not name and "node_modules/" in pkg_path:
                    name = pkg_path.split("node_modules/")[-1]
                if name:
                    deps[name] = entry["version"]

        for _key, entry in data.get("dependencies", {}).items():
            if isinstance(entry, dict) and "version" in entry:
                name = entry.get("name", _key.split("@")[0] if "@" in _key else _key)
                if name and name not in deps:
                    deps[name] = entry["version"]
    except json.JSONDecodeError:
        pass
    return deps


def _load_pnpm_lockfile(content: str) -> dict[str, str]:
    lockfile = parse_pnpm_lockfile(content)
    deps: dict[str, str] = {}


    for importer_deps in lockfile.importers.values():
        for name, version_info in importer_deps.items():
            if isinstance(version_info, str):

                deps[name] = version_info


    for pkg in lockfile.packages.values():

        if pkg.name and pkg.version and pkg.name not in deps:
            deps[pkg.name] = pkg.version

    return deps


def _get_all_dep_versions(pkg: dict) -> dict[str, str]:
    deps: dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        section = pkg.get(key)
        if isinstance(section, dict):
            deps.update(section)
    return deps


def _check_pnpm_workspace(target: Path) -> list[Finding]:
    findings: list[Finding] = []
    workspace_yaml = target / "pnpm-workspace.yaml"
    if not workspace_yaml.is_file():
        return findings

    try:
        content = workspace_yaml.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    if "dangerouslyAllowAllBuilds" in content:
        findings.append(
            Finding(
                rule_id="L2-LOCK-001",
                severity=Severity.CRITICAL,
                confidence=Confidence.EXACT,
                package="root",
                file=str(workspace_yaml),
                message="pnpm-workspace.yaml has dangerouslyAllowAllBuilds enabled",
                evidence="dangerouslyAllowAllBuilds found in pnpm-workspace.yaml",
                remediation=(
                    "Remove dangerouslyAllowAllBuilds and use onlyBuiltDependencies with an explicit allowlist instead."
                ),
                references=[
                    "https://pnpm.io/settings/#dangerouslyallowallbuilds",
                ],
            )
        )

    return findings


def detect_lockfile_drift(target: Path) -> list[Finding]:
    findings: list[Finding] = []


    findings.extend(_check_pnpm_workspace(target))

    root_pkg = target / "package.json"
    if not root_pkg.is_file():
        return findings

    pkg = load_package_json(root_pkg)
    if not pkg:
        return findings

    pkg_deps = _get_all_dep_versions(pkg)


    lockfile = target / "package-lock.json"
    pnpm_lock = target / "pnpm-lock.yaml"
    yarn_lock = target / "yarn.lock"

    lockfile_exists = lockfile.is_file()
    pnpm_exists = pnpm_lock.is_file()
    yarn_exists = yarn_lock.is_file()


    if not lockfile_exists and not pnpm_exists and not yarn_exists:
        if pkg_deps:
            findings.append(
                Finding(
                    rule_id="L2-LOCK-001",
                    severity=Severity.HIGH,
                    confidence=Confidence.EXACT,
                    package=pkg.get("name", "root"),
                    file=str(root_pkg),
                    message=(
                        f"Package has {len(pkg_deps)} dependencies but no lockfile "
                        "(no package-lock.json, pnpm-lock.yaml, or yarn.lock)"
                    ),
                    evidence=f"dependencies: {len(pkg_deps)}, lockfiles: none",
                    remediation=(
                        "Run 'npm install' (or pnpm install / yarn install) to generate a lockfile. "
                        "Always commit lockfiles to ensure reproducible builds."
                    ),
                    references=[
                        "https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json",
                        "https://pnpm.io/git#lockfiles",
                    ],
                )
            )
        return findings


    locked_deps: dict[str, str] = {}
    lockfile_path: Path | None = None

    if lockfile_exists:
        lockfile_path = lockfile
        try:
            content = lockfile.read_text(encoding="utf-8", errors="replace")
            lockfile_version = json.loads(content).get("lockfileVersion", 1)
            locked_deps = _load_lockfile_v2(content) if lockfile_version >= 2 else _load_lockfile_v1(content)
        except (json.JSONDecodeError, OSError):
            findings.append(
                Finding(
                    rule_id="L2-LOCK-001",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    package=pkg.get("name", "root"),
                    file=str(lockfile),
                    message="Lockfile exists but cannot be parsed",
                    evidence=f"file: {lockfile}",
                    remediation="Delete and regenerate the lockfile with 'npm install'.",
                    references=[],
                )
            )
            return findings
    elif pnpm_exists:
        lockfile_path = pnpm_lock
        try:
            content = pnpm_lock.read_text(encoding="utf-8", errors="replace")
            locked_deps = _load_pnpm_lockfile(content)
        except OSError:
            return findings

    if not locked_deps:
        return findings


    for dep_name, requested_version in sorted(pkg_deps.items()):
        if dep_name not in locked_deps:
            findings.append(
                Finding(
                    rule_id="L2-LOCK-001",
                    severity=Severity.HIGH,
                    confidence=Confidence.EXACT,
                    package=dep_name,
                    file=str(root_pkg),
                    message=(f"Dependency '{dep_name}' is in package.json but missing from lockfile"),
                    evidence=f"requested: {requested_version}, locked: <missing>",
                    remediation=(
                        f"Run 'npm install {dep_name}' to add it to the lockfile, "
                        f"or remove it from package.json if unused."
                    ),
                    references=[
                        "https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json",
                    ],
                )
            )


    pkg_dep_names = set(pkg_deps.keys())
    for locked_name in sorted(locked_deps.keys()):

        if locked_name == "" or locked_name == pkg.get("name", ""):
            continue
        if locked_name not in pkg_dep_names:


            pass  # Transitive deps are expected in lockfiles


    if lockfile_exists and lockfile_path:
        try:
            content = lockfile.read_text(encoding="utf-8", errors="replace")
            lock_data = json.loads(content)
            packages = lock_data.get("packages", {})
            missing_integrity = []
            for pkg_path, entry in packages.items():
                if not isinstance(entry, dict):
                    continue

                if not pkg_path:
                    continue
                name = entry.get("name", pkg_path.split("/")[-1] if "/" in pkg_path else pkg_path)
                if "version" in entry and "integrity" not in entry and "link" not in entry:
                    missing_integrity.append(name)

            if missing_integrity:
                findings.append(
                    Finding(
                        rule_id="L2-LOCK-001",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        package=pkg.get("name", "root"),
                        file=str(lockfile),
                        message=(f"{len(missing_integrity)} package(s) in lockfile lack integrity hashes"),
                        evidence=f"missing integrity: {', '.join(missing_integrity[:10])}",
                        remediation=(
                            "Run 'npm install' to regenerate integrity hashes. "
                            "Missing hashes mean the lockfile cannot verify package contents."
                        ),
                        references=[
                            "https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json#integrity",
                        ],
                    )
                )

            weak_integrity = []
            for pkg_path, entry in packages.items():
                if not isinstance(entry, dict):
                    continue
                if not pkg_path:
                    continue
                integrity = entry.get("integrity", "")
                if isinstance(integrity, str):
                    for algo in WEAK_INTEGRITY:
                        if integrity.startswith(algo):
                            name = entry.get("name", pkg_path.split("/")[-1] if "/" in pkg_path else pkg_path)
                            weak_integrity.append((name, algo.rstrip("-")))
                            break

            if weak_integrity:
                findings.append(
                    Finding(
                        rule_id="L2-LOCK-001",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        package=pkg.get("name", "root"),
                        file=str(lockfile),
                        message=(f"{len(weak_integrity)} package(s) in lockfile use weak integrity algorithm"),
                        evidence=f"weak integrity: {', '.join(f'{n} ({a})' for n, a in weak_integrity[:10])}",
                        remediation=(
                            "Run 'npm install' to regenerate integrity hashes with sha512. "
                            "Weak algorithms like sha1 are vulnerable to collision attacks."
                        ),
                        references=[
                            "https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json#integrity",
                            "https://shattered.io/",
                        ],
                    )
                )

        except (json.JSONDecodeError, OSError):
            logger.debug("Failed to read lockfile", exc_info=True)


    if pnpm_exists:
        try:
            pnpm_content = pnpm_lock.read_text(encoding="utf-8", errors="replace")
            pnpm_parsed = parse_pnpm_lockfile(pnpm_content)


            missing = find_missing_integrity(pnpm_parsed)
            if missing:
                findings.append(
                    Finding(
                        rule_id="L2-LOCK-001",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        package=pkg.get("name", "root"),
                        file=str(pnpm_lock),
                        message=(f"{len(missing)} package(s) in pnpm-lock.yaml lack integrity hashes"),
                        evidence=f"missing integrity: {', '.join(f'{n}@{v}' for n, v in missing[:10])}",
                        remediation=(
                            "Run 'pnpm install' to regenerate integrity hashes. "
                            "Missing hashes mean package contents cannot be verified."
                        ),
                        references=[
                            "https://pnpm.io/git#lockfiles",
                        ],
                    )
                )


            weak = find_weak_integrity(pnpm_parsed)
            if weak:
                findings.append(
                    Finding(
                        rule_id="L2-LOCK-001",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        package=pkg.get("name", "root"),
                        file=str(pnpm_lock),
                        message=(f"{len(weak)} package(s) in pnpm-lock.yaml use weak integrity algorithm"),
                        evidence=f"weak integrity: {', '.join(f'{n}@{v} ({a})' for n, v, a in weak[:10])}",
                        remediation=(
                            "Run 'pnpm install' to regenerate integrity hashes with sha512. "
                            "Weak algorithms like sha1 are vulnerable to collision attacks."
                        ),
                        references=[
                            "https://pnpm.io/git#lockfiles",
                            "https://shattered.io/",
                        ],
                    )
                )

        except OSError:
            logger.debug("Failed to read pnpm lockfile", exc_info=True)

    return findings
