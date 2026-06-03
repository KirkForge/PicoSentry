"""
Cargo lockfile parsers.

Parsers for Cargo.lock — Rust's dependency lockfile.
Analogous to Go's go.sum and npm's package-lock.json.

Pure functions. No network calls.
"""

from __future__ import annotations

from pathlib import Path

from .cargo_utils import parse_cargo_lock, parse_cargo_toml


def parse_cargo_lockfile(path: Path) -> list[tuple[str, str, str]]:
    """Auto-detect and parse a Cargo lockfile by filename.

    Supports:
    - ``Cargo.toml`` → dependencies with version constraints
    - ``Cargo.lock`` → pinned versions with source identifiers

    Returns list of ``(crate_name, version, source)`` tuples
    where ``source`` is the filename (for provenance tracking).

    Args:
        path: Path to the lockfile (Cargo.toml or Cargo.lock).

    Returns:
        List of (crate_name, version, source) tuples.
        Empty list if the file doesn't exist or format is unrecognized.
    """
    if not path.is_file():
        return []

    fname = path.name

    if fname == "Cargo.toml":
        return parse_cargo_toml_for_lock(path)
    if fname == "Cargo.lock":
        return parse_cargo_lock_for_lock(path)

    return []


def parse_cargo_toml_for_lock(path: Path) -> list[tuple[str, str, str]]:
    """Parse Cargo.toml for dependency list.

    Returns ``(crate_name, version, "Cargo.toml")`` tuples.
    Includes both regular and dev dependencies.
    """
    cargo_data = parse_cargo_toml(path.parent)
    if cargo_data is None:
        return []

    entries: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    deps = cargo_data.get("dependencies", {})
    for crate_name, version in deps.items():
        if crate_name and version and (crate_name, str(version)) not in seen:
            seen.add((crate_name, str(version)))
            entries.append((crate_name, str(version), "Cargo.toml"))

    dev_deps = cargo_data.get("dev_dependencies", {})
    for crate_name, version in dev_deps.items():
        if crate_name and version and (crate_name, str(version)) not in seen:
            seen.add((crate_name, str(version)))
            entries.append((crate_name, str(version), "Cargo.toml"))

    return entries


def parse_cargo_lock_for_lock(path: Path) -> list[tuple[str, str, str]]:
    """Parse Cargo.lock for pinned dependency versions.

    Returns ``(crate_name, version, "Cargo.lock")`` tuples.
    Deduplicates multiple entries for the same crate+version.
    """
    packages = parse_cargo_lock(path.parent)
    if not packages:
        return []

    result: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    for pkg in packages:
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        if name and version and (name, version) not in seen:
            seen.add((name, version))
            result.append((name, version, "Cargo.lock"))

    return result