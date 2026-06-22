from __future__ import annotations

from pathlib import Path

from .cargo_utils import parse_cargo_lock, parse_cargo_toml


def parse_cargo_lockfile(path: Path) -> list[tuple[str, str, str]]:
    if not path.is_file():
        return []

    fname = path.name

    if fname == "Cargo.toml":
        return parse_cargo_toml_for_lock(path)
    if fname == "Cargo.lock":
        return parse_cargo_lock_for_lock(path)

    return []


def parse_cargo_toml_for_lock(path: Path) -> list[tuple[str, str, str]]:
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
