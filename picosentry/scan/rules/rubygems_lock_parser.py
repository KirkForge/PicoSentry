"""
RubyGems lockfile-parsing wrapper — dispatches by filename to the appropriate parser.

Analogues of ``cargo_lock_parser.py`` but for the RubyGems ecosystem.
"""

from __future__ import annotations

from pathlib import Path

from .rubygems_utils import parse_gemfile, parse_gemfile_lock


def parse_rubygems_lockfile(path: Path) -> list[tuple[str, str, str]]:
    """Auto-detect and parse a RubyGems lockfile by filename.

    Dispatches based on file name:
    - ``Gemfile`` → list of (gem_name, version, "Gemfile")
    - ``Gemfile.lock`` → list of (gem_name, version, "Gemfile.lock")

    Returns list of (dependency_name, version, source) tuples.
    Returns empty list if the file is not recognized or can't be parsed.
    """
    name = path.name

    if name == "Gemfile":
        return parse_gemfile_for_lock(path)
    if name == "Gemfile.lock":
        return parse_gemfile_lock_for_lock(path)

    return []


def parse_gemfile_for_lock(path: Path) -> list[tuple[str, str, str]]:
    """Parse a Gemfile as a "lockfile" and return (gem_name, version, source) tuples."""
    gemfile_data = parse_gemfile(path.parent)
    if gemfile_data is None:
        return []

    results: list[tuple[str, str, str]] = []
    for gem_name, version, source_type in gemfile_data.get("dependencies", []):
        if gem_name:
            results.append((gem_name, version, "Gemfile"))

    return results


def parse_gemfile_lock_for_lock(path: Path) -> list[tuple[str, str, str]]:
    """Parse a Gemfile.lock and return (gem_name, version, source) tuples."""
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