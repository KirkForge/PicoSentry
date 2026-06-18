
from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger("picosentry.cargo_utils")


_CARGO_DEP_SIMPLE_RE = re.compile(
    r'^\s*([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*"([^"]+)"'
)


_CARGO_DEP_TABLE_RE = re.compile(
    r"^\s*([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*\{"
)

_CARGO_DEP_PATH_RE = re.compile(
    r"^\s*([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*\{\s*path\s*="
)

_CARGO_DEP_GIT_RE = re.compile(
    r"^\s*([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*\{\s*git\s*="
)


_CARGO_LOCK_PACKAGE_START = re.compile(r"^\[\[package\]\]$")
_CARGO_LOCK_NAME_RE = re.compile(r'^name\s*=\s*"([^"]+)"')
_CARGO_LOCK_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"')
_CARGO_LOCK_SOURCE_RE = re.compile(r'^source\s*=\s*"([^"]+)"')


_CARGO_SECTION_RE = re.compile(r"^\[([a-zA-Z_][a-zA-Z0-9_.-]*)\]$")


def detect_cargo_project(target: Path) -> bool:
    if not target.is_dir():
        return False

    if (target / "Cargo.toml").is_file():
        return True
    return bool((target / "Cargo.lock").is_file())


def parse_cargo_toml(target: Path) -> dict | None:
    cargo_toml_path = target / "Cargo.toml"
    if not cargo_toml_path.is_file():
        return None

    try:
        lines = cargo_toml_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    result: dict = {
        "package_name": "",
        "version": "",
        "dependencies": {},
        "dev_dependencies": {},
        "build_dependencies": {},
        "patch": {},
        "has_path_deps": set(),
    }

    current_section = ""
    in_patch_target = False

    for line in lines:
        stripped = line.strip()


        if not stripped or stripped.startswith("#"):
            continue


        section_match = _CARGO_SECTION_RE.match(stripped)
        if section_match:
            current_section = section_match.group(1)
            in_patch_target = False
            continue


        if current_section == "package":
            if stripped.startswith("name"):
                name_match = re.match(r'name\s*=\s*"([^"]+)"', stripped)
                if name_match:
                    result["package_name"] = name_match.group(1)
            elif stripped.startswith("version"):
                ver_match = re.match(r'version\s*=\s*"([^"]+)"', stripped)
                if ver_match:
                    result["version"] = ver_match.group(1)
            continue


        if current_section.startswith("patch."):
            in_patch_target = True


        if in_patch_target and "=" in stripped and ("path" in stripped or "git" in stripped):
            pkg_match = re.match(r"^\s*([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*\{", stripped)
            if pkg_match:
                crate = pkg_match.group(1)
                path_match = re.search(r'path\s*=\s*"([^"]+)"', stripped)
                if path_match:
                    result["patch"][crate] = f"path:{path_match.group(1)}"
                git_match = re.search(r'git\s*=\s*"([^"]+)"', stripped)
                if git_match:
                    result["patch"][crate] = f"git:{git_match.group(1)}"
                continue


        dep_target = None
        if current_section == "dependencies":
            dep_target = result["dependencies"]
        elif current_section == "dev-dependencies":
            dep_target = result["dev_dependencies"]
        elif current_section == "build-dependencies":
            dep_target = result["build_dependencies"]

        if dep_target is not None:

            simple_match = _CARGO_DEP_SIMPLE_RE.match(stripped)
            if simple_match:
                crate = simple_match.group(1)
                version = simple_match.group(2)
                dep_target[crate] = version
                continue


            path_match = _CARGO_DEP_PATH_RE.match(stripped)
            if path_match:
                crate = path_match.group(1)
                dep_target[crate] = "path"
                result["has_path_deps"].add(crate)
                continue


            git_match = _CARGO_DEP_GIT_RE.match(stripped)
            if git_match:
                crate = git_match.group(1)
                dep_target[crate] = "git"
                continue


            table_match = _CARGO_DEP_TABLE_RE.match(stripped)
            if table_match:
                crate = table_match.group(1)

                ver_match = re.search(r'version\s*=\s*"([^"]+)"', stripped)
                if ver_match:
                    dep_target[crate] = ver_match.group(1)
                else:
                    dep_target[crate] = "table"
                continue

    return result


def parse_cargo_lock(target: Path) -> list[dict] | None:
    cargo_lock_path = target / "Cargo.lock"
    if not cargo_lock_path.is_file():
        return None

    try:
        lines = cargo_lock_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    packages: list[dict] = []
    current_pkg: dict = {}
    in_package = False

    for line in lines:
        stripped = line.strip()

        if _CARGO_LOCK_PACKAGE_START.match(stripped):

            if in_package and current_pkg.get("name"):
                packages.append(current_pkg)
            current_pkg = {}
            in_package = True
            continue

        if not in_package:
            continue

        name_match = _CARGO_LOCK_NAME_RE.match(stripped)
        if name_match:
            current_pkg["name"] = name_match.group(1)
            continue

        ver_match = _CARGO_LOCK_VERSION_RE.match(stripped)
        if ver_match:
            current_pkg["version"] = ver_match.group(1)
            continue

        source_match = _CARGO_LOCK_SOURCE_RE.match(stripped)
        if source_match:
            current_pkg["source"] = source_match.group(1)
            continue


        checksum_match = re.match(r'^checksum\s*=\s*"([^"]+)"', stripped)
        if checksum_match:
            current_pkg["checksum"] = checksum_match.group(1)
            continue


    if in_package and current_pkg.get("name"):
        packages.append(current_pkg)

    return packages or None


def get_cargo_dep_names(cargo_toml_data: dict) -> set[str]:
    names: set[str] = set()

    for crate_name in cargo_toml_data.get("dependencies", {}):
        if crate_name:
            names.add(crate_name)

    for crate_name in cargo_toml_data.get("dev_dependencies", {}):
        if crate_name:
            names.add(crate_name)

    for crate_name in cargo_toml_data.get("build_dependencies", {}):
        if crate_name:
            names.add(crate_name)

    return names


def detect_private_cargo_registry(target: Path) -> bool:

    cargo_config_paths = [
        target / ".cargo" / "config.toml",
        target / ".cargo" / "config",
    ]
    for config_path in cargo_config_paths:
        if config_path.is_file():
            try:
                content = config_path.read_text(encoding="utf-8", errors="replace")

                if re.search(r"^\s*\[registries\]", content, re.MULTILINE):
                    return True

                if re.search(r"^\s*\[registries\.", content, re.MULTILINE):
                    return True
            except OSError:
                pass


    cargo_toml_data = parse_cargo_toml(target)
    if cargo_toml_data:

        if cargo_toml_data.get("has_path_deps"):
            return True

        if cargo_toml_data.get("patch"):
            return True

    return False
