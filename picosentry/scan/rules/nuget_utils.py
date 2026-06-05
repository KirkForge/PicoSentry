"""
NuGet-specific detection and parsing utilities for .NET projects.

Analogues of ``cargo_utils.py`` but for the NuGet ecosystem.

Provides:
- ``detect_nuget_project()`` — check for .NET indicator files (*.csproj, packages.config)
- ``parse_csproj_file()`` — parse .csproj for PackageReference dependencies
- ``parse_packages_config()`` — parse packages.config for package dependencies
- ``parse_nuget_lock()`` — parse packages.lock.json for pinned versions
- ``get_nuget_dep_names()`` — extract package IDs from parsed data
- ``detect_private_nuget_source()`` — check for private NuGet source configuration
"""

from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

logger = logging.getLogger("picosentry.nuget_utils")

# ── MSBuild XML namespace ─────────────────────────────────────────────────
_MSBUILD_NS = "http://schemas.microsoft.com/developer/msbuild/2003"
_NS = {"msbuild": _MSBUILD_NS}

# ── Package detection ─────────────────────────────────────────────────────


def detect_nuget_project(target: Path) -> bool:
    """Check if the target directory contains a .NET/NuGet project.

    Returns True if any of these indicator files exist:
    - *.csproj (C# project file)
    - packages.config (legacy NuGet format)
    - packages.lock.json (lockfile)
    - *.sln (solution file)
    - nuget.config (NuGet configuration)
    """
    if not target.is_dir():
        return False

    if (target / "packages.config").is_file():
        return True
    if (target / "packages.lock.json").is_file():
        return True
    if (target / "nuget.config").is_file():
        return True
    if list(target.glob("*.csproj")):
        return True
    return bool(list(target.glob("*.sln")))


# ── .csproj parsing ────────────────────────────────────────────────────────


def parse_csproj_file(target: Path) -> dict | None:
    """Parse ``.csproj`` file(s) for PackageReference dependencies.

    Scans for all *.csproj files in the target directory. Each is parsed
    with ElementTree using the MSBuild XML namespace.

    Returns a dict with:
    - ``project_name``: project name (AssemblyName or filename stem)
    - ``package_references``: list of (package_id, version) tuples
    - ``project_references``: list of relative project paths
    - ``target_framework``: target framework moniker

    Returns None if no *.csproj files exist.
    """
    csproj_files = list(target.glob("*.csproj"))
    if not csproj_files:
        return None

    result: dict = {
        "project_name": "",
        "package_references": [],
        "project_references": [],
        "target_framework": "",
    }

    for csproj_path in csproj_files:
        try:
            tree = ET.parse(csproj_path)
        except (ET.ParseError, OSError) as exc:
            logger.debug("Failed to parse %s: %s", csproj_path.name, exc)
            continue

        root = tree.getroot()

        # Try with namespace first, fall back to no namespace
        # _find uses recursive .// because targets (AssemblyName, TargetFramework)
        # are nested under PropertyGroup
        def _find(tag: str, parent: ET.Element = root) -> ET.Element | None:
            result_elem = parent.find(f".//msbuild:{tag}", _NS)
            if result_elem is not None:
                return result_elem
            return parent.find(f".//{tag}")

        # _findall uses direct children find (ItemGroup is always a direct child of Project)
        def _findall(tag: str, parent: ET.Element = root) -> list[ET.Element]:
            result_elem = parent.findall(f"msbuild:{tag}", _NS)
            if result_elem:
                return result_elem
            return parent.findall(tag)

        # Project name
        if not result["project_name"]:
            asm_name = _find("AssemblyName")
            if asm_name is not None:
                result["project_name"] = asm_name.text or ""
            if not result["project_name"]:
                result["project_name"] = csproj_path.stem

        # Target framework
        if not result["target_framework"]:
            tf = _find("TargetFramework")
            if tf is not None:
                result["target_framework"] = tf.text or ""
            else:
                tfs = _find("TargetFrameworks")
                if tfs is not None:
                    result["target_framework"] = (tfs.text or "").split(";")[0]

        # PackageReference items
        for pr in _findall("ItemGroup", root):
            for pkg in _findall("PackageReference", pr):
                include = pkg.get("Include", "")
                version = pkg.get("Version", "")
                if include:
                    result["package_references"].append((include, version))

            for proj_ref in _findall("ProjectReference", pr):
                include = proj_ref.get("Include", "")
                if include:
                    result["project_references"].append(include)

    return result


# ── packages.config parsing ────────────────────────────────────────────────


def parse_packages_config(target: Path) -> list[tuple[str, str]] | None:
    """Parse ``packages.config`` for NuGet package dependencies.

    Returns list of (package_id, version) tuples.
    Returns None if packages.config doesn't exist.
    """
    config_path = target / "packages.config"
    if not config_path.is_file():
        return None

    try:
        tree = ET.parse(config_path)
    except (ET.ParseError, OSError) as exc:
        logger.debug("Failed to parse packages.config: %s", exc)
        return None

    root = tree.getroot()
    packages: list[tuple[str, str]] = []

    for pkg in root.findall("package"):
        pkg_id = pkg.get("id", "")
        version = pkg.get("version", "")
        if pkg_id:
            packages.append((pkg_id, version))

    return packages if packages else None


# ── packages.lock.json parsing ─────────────────────────────────────────────


def parse_nuget_lock(target: Path) -> list[dict] | None:
    """Parse ``packages.lock.json`` for pinned NuGet package versions.

    packages.lock.json is generated by ``dotnet restore`` with lock file support.

    Returns list of dicts with:
    - ``name``: package ID
    - ``version``: resolved version
    - ``type``: "Direct" or "Transitive"

    Returns None if packages.lock.json doesn't exist.
    """
    lock_path = target / "packages.lock.json"
    if not lock_path.is_file():
        return None

    try:
        data = json.loads(lock_path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("Failed to parse packages.lock.json: %s", exc)
        return None

    packages: list[dict] = []

    # Structure: {"version": 1, "dependencies": { "project": { "type": "Project", "dependencies": { ... } } }
    deps_section = data.get("dependencies", {})
    for project_name, project_info in deps_section.items():
        project_deps = project_info.get("dependencies", {})
        for pkg_name, pkg_info in project_deps.items():
            packages.append({
                "name": pkg_name,
                "version": pkg_info.get("resolved", pkg_info.get("requested", "")),
                "type": pkg_info.get("type", "Transitive"),
            })

    return packages if packages else None


# ── Unified dependency collection ──────────────────────────────────────────


def collect_nuget_deps(target: Path) -> list[tuple[str, str, str]]:
    """Collect all NuGet dependencies from all sources.

    Returns list of (package_id, version, source) tuples.
    Sources: "csproj", "packages.config", "packages.lock.json"
    """
    deps: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    # From .csproj PackageReference
    csproj_data = parse_csproj_file(target)
    if csproj_data:
        for pkg_id, version in csproj_data.get("package_references", []):
            if pkg_id and (pkg_id, version) not in seen:
                seen.add((pkg_id, version))
                deps.append((pkg_id, version, "csproj"))

    # From packages.config
    config_packages = parse_packages_config(target)
    if config_packages:
        for pkg_id, version in config_packages:
            if (pkg_id, version) not in seen:
                seen.add((pkg_id, version))
                deps.append((pkg_id, version, "packages.config"))

    # From packages.lock.json (more precise resolved versions)
    lock_packages = parse_nuget_lock(target)
    if lock_packages:
        for pkg in lock_packages:
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if name and version and (name, version) not in seen:
                seen.add((name, version))
                deps.append((name, version, "packages.lock.json"))

    return deps


# ── Dependency name extraction ─────────────────────────────────────────────


def get_nuget_dep_names(nuget_data: dict | list) -> set[str]:
    """Extract dependency package IDs from parsed NuGet data.

    Accepts either the dict from parse_csproj_file() or the list
    from parse_packages_config().

    Returns a set of package ID strings (e.g. ``Newtonsoft.Json``).
    """
    names: set[str] = set()

    if isinstance(nuget_data, dict):
        for pkg_id, version in nuget_data.get("package_references", []):
            if pkg_id:
                names.add(pkg_id)

    elif isinstance(nuget_data, list):
        for pkg_id, version in nuget_data:
            if pkg_id:
                names.add(pkg_id)

    return names


# ── Private NuGet source detection ────────────────────────────────────────


def _is_public_nuget_url(url: str) -> bool:
    """Check if a URL is the official public NuGet gallery."""
    url_lower = url.lower().rstrip("/")
    public_patterns = [
        "api.nuget.org",
        "nuget.org",
        "ms.microsoft.com",
        "go.microsoft.com",
    ]
    return any(pattern in url_lower for pattern in public_patterns)


def detect_private_nuget_source(target: Path) -> bool:
    """Check if a private NuGet package source is configured.

    Looks for:
    - ``nuget.config`` with custom <packageSources> (non-public URLs)
    - NuGet.config (case-insensitive)
    - csproj project references (indicates local dependencies)

    Returns True if any private source configuration is found.
    """
    # Check nuget.config
    for config_name in ("nuget.config", "NuGet.config", "nuget.Config"):
        config_path = target / config_name
        if not config_path.is_file():
            continue

        try:
            tree = ET.parse(config_path)
        except (ET.ParseError, OSError):
            continue

        root = tree.getroot()
        # Look for packageSources with custom URLs
        package_sources = root.findall(".//add")
        for add_elem in package_sources:
            url = add_elem.get("value", "")
            if url and not _is_public_nuget_url(url):
                return True

        # Check for <clear /> before packageSources
        for clear_elem in root.findall(".//clear"):
            return True

    # Check csproj for project references (local deps)
    csproj_data = parse_csproj_file(target)
    return bool(csproj_data and csproj_data.get("project_references"))
