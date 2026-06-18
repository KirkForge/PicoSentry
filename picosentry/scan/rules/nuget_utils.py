
from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

logger = logging.getLogger("picosentry.nuget_utils")


_MSBUILD_NS = "http://schemas.microsoft.com/developer/msbuild/2003"
_NS = {"msbuild": _MSBUILD_NS}


def detect_nuget_project(target: Path) -> bool:
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


def parse_csproj_file(target: Path) -> dict | None:
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


        def _find(tag: str, parent: ET.Element = root) -> ET.Element | None:
            result_elem = parent.find(f".//msbuild:{tag}", _NS)
            if result_elem is not None:
                return result_elem
            return parent.find(f".//{tag}")


        def _findall(tag: str, parent: ET.Element = root) -> list[ET.Element]:
            result_elem = parent.findall(f"msbuild:{tag}", _NS)
            if result_elem:
                return result_elem
            return parent.findall(tag)


        if not result["project_name"]:
            asm_name = _find("AssemblyName")
            if asm_name is not None:
                result["project_name"] = asm_name.text or ""
            if not result["project_name"]:
                result["project_name"] = csproj_path.stem


        if not result["target_framework"]:
            tf = _find("TargetFramework")
            if tf is not None:
                result["target_framework"] = tf.text or ""
            else:
                tfs = _find("TargetFrameworks")
                if tfs is not None:
                    result["target_framework"] = (tfs.text or "").split(";")[0]


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


def parse_packages_config(target: Path) -> list[tuple[str, str]] | None:
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

    return packages or None


def parse_nuget_lock(target: Path) -> list[dict] | None:
    lock_path = target / "packages.lock.json"
    if not lock_path.is_file():
        return None

    try:
        data = json.loads(lock_path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("Failed to parse packages.lock.json: %s", exc)
        return None

    packages: list[dict] = []


    deps_section = data.get("dependencies", {})
    for project_info in deps_section.values():
        project_deps = project_info.get("dependencies", {})
        for pkg_name, pkg_info in project_deps.items():
            packages.append({
                "name": pkg_name,
                "version": pkg_info.get("resolved", pkg_info.get("requested", "")),
                "type": pkg_info.get("type", "Transitive"),
            })

    return packages or None


def collect_nuget_deps(target: Path) -> list[tuple[str, str, str]]:
    deps: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()


    csproj_data = parse_csproj_file(target)
    if csproj_data:
        for pkg_id, version in csproj_data.get("package_references", []):
            if pkg_id and (pkg_id, version) not in seen:
                seen.add((pkg_id, version))
                deps.append((pkg_id, version, "csproj"))


    config_packages = parse_packages_config(target)
    if config_packages:
        for pkg_id, version in config_packages:
            if (pkg_id, version) not in seen:
                seen.add((pkg_id, version))
                deps.append((pkg_id, version, "packages.config"))


    lock_packages = parse_nuget_lock(target)
    if lock_packages:
        for pkg in lock_packages:
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if name and version and (name, version) not in seen:
                seen.add((name, version))
                deps.append((name, version, "packages.lock.json"))

    return deps


def get_nuget_dep_names(nuget_data: dict | list) -> set[str]:
    names: set[str] = set()

    if isinstance(nuget_data, dict):
        for pkg_id, _version in nuget_data.get("package_references", []):
            if pkg_id:
                names.add(pkg_id)

    elif isinstance(nuget_data, list):
        for pkg_id, _version in nuget_data:
            if pkg_id:
                names.add(pkg_id)

    return names


def _is_public_nuget_url(url: str) -> bool:
    url_lower = url.lower().rstrip("/")
    public_patterns = [
        "api.nuget.org",
        "nuget.org",
        "ms.microsoft.com",
        "go.microsoft.com",
    ]
    return any(pattern in url_lower for pattern in public_patterns)


def detect_private_nuget_source(target: Path) -> bool:

    for config_name in ("nuget.config", "NuGet.config", "nuget.Config"):
        config_path = target / config_name
        if not config_path.is_file():
            continue

        try:
            tree = ET.parse(config_path)
        except (ET.ParseError, OSError):
            continue

        root = tree.getroot()

        package_sources = root.findall(".//add")
        for add_elem in package_sources:
            url = add_elem.get("value", "")
            if url and not _is_public_nuget_url(url):
                return True


        for _clear_elem in root.findall(".//clear"):
            return True


    csproj_data = parse_csproj_file(target)
    return bool(csproj_data and csproj_data.get("project_references"))
