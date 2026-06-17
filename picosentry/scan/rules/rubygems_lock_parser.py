
from __future__ import annotations

from pathlib import Path

from .rubygems_utils import parse_gemfile, parse_gemfile_lock


def parse_rubygems_lockfile(path: Path) -> list[tuple[str, str, str]]:
    name = path.name

    if name == "Gemfile":
        return parse_gemfile_for_lock(path)
    if name == "Gemfile.lock":
        return parse_gemfile_lock_for_lock(path)

    return []


def parse_gemfile_for_lock(path: Path) -> list[tuple[str, str, str]]:
    gemfile_data = parse_gemfile(path.parent)
    if gemfile_data is None:
        return []

    results: list[tuple[str, str, str]] = []
    for gem_name, version, _source_type in gemfile_data.get("dependencies", []):
        if gem_name:
            results.append((gem_name, version, "Gemfile"))

    return results


def parse_gemfile_lock_for_lock(path: Path) -> list[tuple[str, str, str]]:
    lock_gems = parse_gemfile_lock(path.parent)
    if lock_gems is None:
        return []

    results: list[tuple[str, str, str]] = []
    for gem in lock_gems:
        name = gem.get("name", "")
        version = gem.get("version", "")
        if name:
            results.append((name, version, "Gemfile.lock"))

    return results
