"""
PnpmLockParser — Parse pnpm-lock.yaml v6+ for deterministic lockfile analysis.

Extracts packages, versions, integrity hashes, and resolution info from
pnpm-lock.yaml without making any network calls.

Supports v6+ format (lockfileVersion: 6.x, 9.x).
Falls back to regex parsing for older formats.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass(frozen=True)
class PnpmPackage:
    """A resolved package from pnpm-lock.yaml."""

    name: str
    version: str
    resolution: str = ""
    integrity: str = ""
    deps: tuple[str, ...] = ()
    is_aliased: bool = False


@dataclass
class PnpmLockfile:
    """Parsed pnpm-lock.yaml structure."""

    lockfile_version: str = ""
    importers: dict[str, dict[str, str]] = field(default_factory=dict)
    packages: dict[str, PnpmPackage] = field(default_factory=dict)
    checksums: dict[str, str] = field(default_factory=dict)


def parse_pnpm_lockfile(content: str) -> PnpmLockfile:
    """Parse pnpm-lock.yaml content into a PnpmLockfile structure.

    Supports v6+ format with YAML parsing (when PyYAML available).
    Falls back to regex-based parsing for older formats.
    """
    if YAML_AVAILABLE:
        return _parse_with_yaml(content)
    return _parse_with_regex(content)


def _parse_with_yaml(content: str) -> PnpmLockfile:
    """Parse pnpm-lock.yaml using PyYAML for v6+ format."""
    lockfile = PnpmLockfile()

    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        return lockfile

    if not isinstance(data, dict):
        return lockfile

    # Lockfile version
    lockfile.lockfile_version = str(data.get("lockfileVersion", ""))

    # Importers (workspace projects)
    importers = data.get("importers", {})
    if isinstance(importers, dict):
        for importer_path, importer_data in importers.items():
            if isinstance(importer_data, dict):
                deps = {}
                for dep_type in ("dependencies", "devDependencies", "optionalDependencies"):
                    section = importer_data.get(dep_type, {})
                    if isinstance(section, dict):
                        for name, version_info in section.items():
                            if isinstance(version_info, str):
                                deps[name] = version_info
                            elif isinstance(version_info, dict):
                                deps[name] = version_info.get("version", str(version_info))
                lockfile.importers[importer_path] = deps

    # Packages (v6+ format: "name@version(scope)": {...})
    packages = data.get("packages", {})
    if isinstance(packages, dict):
        for pkg_key, pkg_data in packages.items():
            if not isinstance(pkg_data, dict):
                continue
            name, version, is_aliased = _parse_pnpm_pkg_key(pkg_key)
            if not name:
                continue

            resolution = ""
            res = pkg_data.get("resolution", {})
            if isinstance(res, dict):
                resolution = res.get("integrity", "")
            elif isinstance(res, str):
                resolution = res

            integrity = pkg_data.get("resolution", {})
            integrity = integrity.get("integrity", "") if isinstance(integrity, dict) else ""

            # Dependencies listed under this package
            pkg_deps: list[str] = []
            for dep_type in ("dependencies", "optionalDependencies"):
                dep_section = pkg_data.get(dep_type, {})
                if isinstance(dep_section, dict):
                    pkg_deps.extend(sorted(dep_section.keys()))

            lockfile.packages[pkg_key] = PnpmPackage(
                name=name,
                version=version or pkg_data.get("version", ""),
                resolution=resolution,
                integrity=integrity,
                deps=tuple(pkg_deps),
                is_aliased=is_aliased,
            )

    return lockfile


def _parse_pnpm_pkg_key(key: str) -> tuple[str, str, bool]:
    """Parse a pnpm-lock.yaml package key into (name, version, is_aliased).

    Examples:
        '/lodash@4.17.21' → ('lodash', '4.17.21', False)
        '/@types/node@20.0.0' → ('@types/node', '20.0.0', False)
        '/react@18.2.0(react-dom@18.2.0)' → ('react', '18.2.0', True)
    """
    # Strip leading slash
    key = key.lstrip("/")

    # Check for peer deps suffix like (react-dom@18.2.0)
    is_aliased = "(" in key
    key = key.split("(")[0]

    # Scoped package: @scope/name@version
    if key.startswith("@"):
        # Find second @ (after @scope)
        at_idx = key.find("@", 1)
        if at_idx > 0:
            return key[:at_idx], key[at_idx + 1 :], is_aliased
        return key, "", is_aliased

    # Regular: name@version
    at_idx = key.find("@")
    if at_idx > 0:
        return key[:at_idx], key[at_idx + 1 :], is_aliased

    return key, "", is_aliased


def _parse_with_regex(content: str) -> PnpmLockfile:
    """Fallback regex parser for pnpm-lock.yaml (v5 and earlier)."""
    lockfile = PnpmLockfile()

    # Extract lockfileVersion
    version_match = re.search(r"lockfileVersion:\s*['\"]?([\d.]+)", content)
    if version_match:
        lockfile.lockfile_version = version_match.group(1)

    # Extract packages: /packageName@version
    for line in content.splitlines():
        stripped = line.strip()
        # Match: '/packageName@version':
        m = re.match(r"^['\"]?/([^@]+)@([\d.]+[^'\":]*)['\"]?:", stripped)
        if m:
            name = m.group(1)
            version = m.group(2).rstrip("'\"")
            key = f"/{name}@{version}"
            lockfile.packages[key] = PnpmPackage(
                name=name,
                version=version,
            )

    # Extract importers (basic)
    in_importers = False
    for line in content.splitlines():
        if line.strip() == "importers:":
            in_importers = True
            continue
        if in_importers:
            if line.startswith("  ") or line.startswith("\t"):
                # Sub-line of importer
                pass
            else:
                # New importer or end of importers section
                m = re.match(r"^\s+['\"]?([^'\":]+)['\"]?:", line)
                if m:
                    m.group(1)
                else:
                    in_importers = False

    return lockfile


def get_pnpm_importer_deps(lockfile: PnpmLockfile, importer: str = ".") -> dict[str, str]:
    """Get all dependencies declared by a specific importer (workspace project)."""
    return lockfile.importers.get(importer, {})


def get_pnpm_package(lockfile: PnpmLockfile, name: str, version: str | None = None) -> PnpmPackage | None:
    """Look up a package by name (and optionally version) in the lockfile."""
    for pkg in lockfile.packages.values():
        if pkg.name == name and (version is None or pkg.version == version):
            return pkg
    return None


def find_missing_integrity(lockfile: PnpmLockfile) -> list[tuple[str, str]]:
    """Find packages in the lockfile that lack integrity hashes.

    Returns list of (name, version) tuples.
    """
    missing = []
    for pkg in lockfile.packages.values():
        if not pkg.integrity and not pkg.resolution:
            missing.append((pkg.name, pkg.version))
    return missing


def find_weak_integrity(lockfile: PnpmLockfile) -> list[tuple[str, str, str]]:
    """Find packages using weak integrity algorithms (sha1, md5).

    Returns list of (name, version, algorithm) tuples.
    """
    # sha256 is not weak per se, but sha512 is preferred
    # Only flag sha1 and md5 as truly weak
    truly_weak = ("sha1-", "md5-")
    weak = []
    for pkg in lockfile.packages.values():
        integrity = pkg.integrity or pkg.resolution
        if integrity:
            for algo in truly_weak:
                if algo in integrity:
                    weak.append((pkg.name, pkg.version, algo.rstrip("-")))
                    break
    return weak
