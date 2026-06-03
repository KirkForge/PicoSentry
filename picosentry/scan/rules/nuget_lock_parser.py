"""
NuGet lockfile-parsing wrapper — dispatches by filename to the appropriate parser.

Analogues of ``cargo_lock_parser.py`` but for the NuGet ecosystem.
"""

from __future__ import annotations

from pathlib import Path

from .nuget_utils import parse_csproj_file, parse_packages_config, parse_nuget_lock


def parse_nuget_lockfile(path: Path) -> list[tuple[str, str, str]]:
    """Auto-detect and parse a NuGet file by filename.

    Dispatches based on file name/suffix:
    - ``*.csproj`` → list of (package_id, version, "csproj")
    - ``packages.config`` → list of (package_id, version, "packages.config")
    - ``packages.lock.json`` → list of (package_id, version, "packages.lock.json")

    Returns list of (dependency_name, version, source) tuples.
    Returns empty list if the file is not recognized or can't be parsed.
    """
    name = path.name

    if path.suffix == ".csproj":
        return parse_csproj_for_lock(path)
    if name == "packages.config":
        return parse_packages_config_for_lock(path)
    if name == "packages.lock.json":
        return parse_nuget_lock_for_lock(path)

    return []


def parse_csproj_for_lock(path: Path) -> list[tuple[str, str, str]]:
    """Parse a .csproj file and return (package_id, version, source) tuples."""
    csproj_data = parse_csproj_file(path.parent)
    if csproj_data is None:
        return []

    results: list[tuple[str, str, str]] = []
    for pkg_id, version in csproj_data.get("package_references", []):
        if pkg_id:
            results.append((pkg_id, version, "csproj"))

    return results


def parse_packages_config_for_lock(path: Path) -> list[tuple[str, str, str]]:
    """Parse a packages.config and return (package_id, version, source) tuples."""
    packages = parse_packages_config(path.parent)
    if packages is None:
        return []

    return [(pkg_id, version, "packages.config") for pkg_id, version in packages]


def parse_nuget_lock_for_lock(path: Path) -> list[tuple[str, str, str]]:
    """Parse a packages.lock.json and return (package_id, version, source) tuples."""
    lock_packages = parse_nuget_lock(path.parent)
    if lock_packages is None:
        return []

    results: list[tuple[str, str, str]] = []
    for pkg in lock_packages:
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        if name:
            results.append((name, version, "packages.lock.json"))

    return results