"""
Cargo-specific iteration and parsing utilities for Rust projects.

Analogues of ``go_utils.py`` but for the Rust/Cargo ecosystem.

Provides:
- ``detect_cargo_project()`` — check for Cargo indicator files (Cargo.toml)
- ``parse_cargo_toml()`` — parse Cargo.toml for package metadata and dependencies
- ``parse_cargo_lock()`` — parse Cargo.lock for pinned dependency versions
- ``get_cargo_dep_names()`` — extract dependency crate names from parsed Cargo.toml
- ``detect_private_cargo_registry()`` — check for private registry or patch config
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger("picosentry.cargo_utils")

# ── Cargo patterns ──────────────────────────────────────────────────────

# Dependency line: serde = "1.0"  or  serde = { version = "1.0", ... }
_CARGO_DEP_SIMPLE_RE = re.compile(
    r'^\s*([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*"([^"]+)"'
)
# Dependency with inline table: serde = { version = "1.0", ... }
# This captures the crate name; version is parsed separately if needed
_CARGO_DEP_TABLE_RE = re.compile(
    r'^\s*([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*\{'
)
# Dependency with path: serde = { path = "../local", ... }
_CARGO_DEP_PATH_RE = re.compile(
    r'^\s*([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*\{\s*path\s*='
)
# Dependency with git: serde = { git = "https://..." }
_CARGO_DEP_GIT_RE = re.compile(
    r'^\s*([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*\{\s*git\s*='
)

# Cargo.lock [[package]] entry patterns
_CARGO_LOCK_PACKAGE_START = re.compile(r'^\[\[package\]\]$')
_CARGO_LOCK_NAME_RE = re.compile(r'^name\s*=\s*"([^"]+)"')
_CARGO_LOCK_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"')
_CARGO_LOCK_SOURCE_RE = re.compile(r'^source\s*=\s*"([^"]+)"')

# Cargo.toml section headers
_CARGO_SECTION_RE = re.compile(r'^\[([a-zA-Z_][a-zA-Z0-9_.-]*)\]$')

# ── Package detection ──────────────────────────────────────────────────


def detect_cargo_project(target: Path) -> bool:
    """Check if the target directory contains a Rust/Cargo project.

    Returns True if any of these indicator files exist:
    - Cargo.toml (primary manifest)
    """
    if not target.is_dir():
        return False

    if (target / "Cargo.toml").is_file():
        return True
    if (target / "Cargo.lock").is_file():
        return True

    return False


# ── Cargo.toml parsing ───────────────────────────────────────────────────


def parse_cargo_toml(target: Path) -> dict | None:
    """Parse ``Cargo.toml`` for package metadata and dependencies.

    Returns a dict with:
    - ``package_name``: the crate name (from [package] name)
    - ``version``: the crate version (from [package] version)
    - ``dependencies``: dict of ``{crate_name: version_or_config}``
    - ``dev_dependencies``: dict of ``{crate_name: version_or_config}``
    - ``build_dependencies``: dict of ``{crate_name: version_or_config}``
    - ``patch``: dict of ``{crate_name: source_or_path}``
    - ``has_path_deps``: set of crate names with path dependencies

    Returns None if Cargo.toml doesn't exist or is unparseable.
    """
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
    patch_target_name = ""

    for line in lines:
        stripped = line.strip()

        # Skip comments and blank lines
        if not stripped or stripped.startswith("#"):
            continue

        # Section header
        section_match = _CARGO_SECTION_RE.match(stripped)
        if section_match:
            current_section = section_match.group(1)
            in_patch_target = False
            patch_target_name = ""
            continue

        # [package] fields
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

        # [patch.*] sections — crates being overridden
        # Format: [patch.crates-io] then lines like serde = { path = "..." }
        if current_section.startswith("patch."):
            in_patch_target = True

        # Lines inside [patch.*] sections: crate = { path = "..." } or crate = { git = "..." }
        if in_patch_target and "=" in stripped and ("path" in stripped or "git" in stripped):
            pkg_match = re.match(r'^\s*([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*\{', stripped)
            if pkg_match:
                crate = pkg_match.group(1)
                path_match = re.search(r'path\s*=\s*"([^"]+)"', stripped)
                if path_match:
                    result["patch"][crate] = f"path:{path_match.group(1)}"
                git_match = re.search(r'git\s*=\s*"([^"]+)"', stripped)
                if git_match:
                    result["patch"][crate] = f"git:{git_match.group(1)}"
                continue

        # Dependencies
        dep_target = None
        if current_section == "dependencies":
            dep_target = result["dependencies"]
        elif current_section == "dev-dependencies":
            dep_target = result["dev_dependencies"]
        elif current_section == "build-dependencies":
            dep_target = result["build_dependencies"]

        if dep_target is not None:
            # Simple: crate = "version"
            simple_match = _CARGO_DEP_SIMPLE_RE.match(stripped)
            if simple_match:
                crate = simple_match.group(1)
                version = simple_match.group(2)
                dep_target[crate] = version
                continue

            # Path dependency: crate = { path = "..." }
            path_match = _CARGO_DEP_PATH_RE.match(stripped)
            if path_match:
                crate = path_match.group(1)
                dep_target[crate] = "path"
                result["has_path_deps"].add(crate)
                continue

            # Git dependency: crate = { git = "..." }
            git_match = _CARGO_DEP_GIT_RE.match(stripped)
            if git_match:
                crate = git_match.group(1)
                dep_target[crate] = "git"
                continue

            # Inline table: crate = { version = "...", ... }
            table_match = _CARGO_DEP_TABLE_RE.match(stripped)
            if table_match:
                crate = table_match.group(1)
                # Check if version is in this inline table
                ver_match = re.search(r'version\s*=\s*"([^"]+)"', stripped)
                if ver_match:
                    dep_target[crate] = ver_match.group(1)
                else:
                    dep_target[crate] = "table"
                continue

    return result


# ── Cargo.lock parsing ───────────────────────────────────────────────────


def parse_cargo_lock(target: Path) -> list[dict] | None:
    """Parse ``Cargo.lock`` for pinned dependency versions.

    Cargo.lock is TOML with ``[[package]]`` sections. Each section has:
    - ``name``: crate name
    - ``version``: pinned version
    - ``source``: registry+, git+, or path+ source identifier
    - ``checksum``: optional content hash

    Returns list of dicts with ``name``, ``version``, ``source``, ``checksum``.
    Returns None if Cargo.lock doesn't exist.
    """
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
            # Save previous package if we were in one
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

        # Checksum line (not commonly used)
        checksum_match = re.match(r'^checksum\s*=\s*"([^"]+)"', stripped)
        if checksum_match:
            current_pkg["checksum"] = checksum_match.group(1)
            continue

    # Save the last package
    if in_package and current_pkg.get("name"):
        packages.append(current_pkg)

    return packages if packages else None


# ── Dependency name extraction ──────────────────────────────────────────


def get_cargo_dep_names(cargo_toml_data: dict) -> set[str]:
    """Extract dependency crate names from parsed Cargo.toml data.

    Returns a set of crate names (e.g. ``serde``, ``tokio``).
    Includes dependencies, dev-dependencies, and build-dependencies.
    """
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


# ── Private registry detection ──────────────────────────────────────────


def detect_private_cargo_registry(target: Path) -> bool:
    """Check if a private Cargo registry is configured.

    Looks for:
    - ``[registries]`` section in ``.cargo/config.toml``
    - ``[registries]`` section in ``.cargo/config`` (legacy TOML)
    - ``[patch]`` sections with local path overrides in Cargo.toml
    - ``Cargo.toml`` dependencies with path sources

    Returns True if any private registry config is found.
    """
    # Check .cargo/config.toml or .cargo/config
    cargo_config_paths = [
        target / ".cargo" / "config.toml",
        target / ".cargo" / "config",
    ]
    for config_path in cargo_config_paths:
        if config_path.is_file():
            try:
                content = config_path.read_text(encoding="utf-8", errors="replace")
                # Look for [registries] section which defines private registries
                if re.search(r'^\s*\[registries\]', content, re.MULTILINE):
                    return True
                # Look for registry configuration with custom index URL
                if re.search(r'^\s*\[registries\.', content, re.MULTILINE):
                    return True
            except OSError:
                pass

    # Check Cargo.toml for path dependencies or patch sections
    cargo_toml_data = parse_cargo_toml(target)
    if cargo_toml_data:
        # Path dependencies indicate private/internal crate usage
        if cargo_toml_data.get("has_path_deps"):
            return True
        # Patch sections with path/git overrides
        if cargo_toml_data.get("patch"):
            return True

    return False