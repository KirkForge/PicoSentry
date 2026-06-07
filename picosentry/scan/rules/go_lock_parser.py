
from __future__ import annotations

from pathlib import Path

from .go_utils import parse_go_mod, parse_go_sum


def parse_go_lockfile(path: Path) -> list[tuple[str, str, str]]:
    if not path.is_file():
        return []

    fname = path.name

    if fname == "go.mod":
        return parse_go_mod_for_lock(path)
    if fname == "go.sum":
        return parse_go_sum_for_lock(path)

    return []


def parse_go_mod_for_lock(path: Path) -> list[tuple[str, str, str]]:
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
