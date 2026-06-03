"""
Go lockfile parsers.

Parsers for go.mod and go.sum — Go's dependency management files.
Analogous to npm's package-lock.json / yarn.lock and PyPI's poetry.lock / uv.lock.

Pure functions. No network calls.
"""

from __future__ import annotations

from pathlib import Path

from .go_utils import parse_go_mod, parse_go_sum


def parse_go_lockfile(path: Path) -> list[tuple[str, str, str]]:
    """Auto-detect and parse a Go lockfile by filename.

    Supports:
    - ``go.mod`` → dependencies with version constraints
    - ``go.sum`` → pinned versions with content hashes

    Returns list of ``(module_path, version, source)`` tuples
    where ``source`` is the filename (for provenance tracking).

    Args:
        path: Path to the lockfile (go.mod or go.sum).

    Returns:
        List of (module_path, version, source) tuples.
        Empty list if the file doesn't exist or format is unrecognized.
    """
    if not path.is_file():
        return []

    fname = path.name

    if fname == "go.mod":
        return parse_go_mod_for_lock(path)
    if fname == "go.sum":
        return parse_go_sum_for_lock(path)

    return []


def parse_go_mod_for_lock(path: Path) -> list[tuple[str, str, str]]:
    """Parse go.mod for dependency list.

    Returns ``(module_path, version, "go.mod")`` tuples.
    Includes both direct and indirect dependencies.
    """
    go_mod_data = parse_go_mod(path.parent)
    if go_mod_data is None:
        return []

    entries: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    for mod_path, version in go_mod_data.get("require", []):
        if mod_path and version and (mod_path, version) not in seen:
            seen.add((mod_path, version))
            entries.append((mod_path, version, "go.mod"))

    for mod_path, version in go_mod_data.get("indirect", []):
        if mod_path and version and (mod_path, version) not in seen:
            seen.add((mod_path, version))
            entries.append((mod_path, version, "go.mod"))

    return entries


def parse_go_sum_for_lock(path: Path) -> list[tuple[str, str, str]]:
    """Parse go.sum for pinned dependency versions.

    Returns ``(module_path, version, "go.sum")`` tuples.
    Deduplicates multiple hash lines for the same module+version.
    """
    entries = parse_go_sum(path.parent)
    if not entries:
        return []

    result: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    for mod_path, version, _hash_val in entries:
        if (mod_path, version) not in seen:
            seen.add((mod_path, version))
            result.append((mod_path, version, "go.sum"))

    return result