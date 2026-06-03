"""
PyPI lockfile parsers — deterministic, no-network, pure functions.

Parses three Python lockfile formats:
- ``requirements.txt`` / pip freeze output
- ``poetry.lock`` (TOML format)
- ``uv.lock`` (TOML format with hash arrays)

All return the same structure: ``list[(name, version, extras)]``
where extras is a dict of optional metadata (hashes, markers).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger("picosentry.pypi_lock_parser")


# ── Shared types ────────────────────────────────────────────────────────

# Each entry: (package_name, version, extras_dict)
LockEntry = tuple[str, str, dict]


# ── Requirements.txt / pip freeze parser ───────────────────────────────


def parse_requirements_txt(path: Path) -> list[LockEntry]:
    """Parse a ``requirements.txt`` or ``pip freeze`` output file.

    Handles:
    - ``package==version`` (precise pinning)
    - ``package>=version,<version`` (range pins)
    - ``package`` (no version constraint — version set to "*")
    - ``# comments`` and ``-r includes`` (skipped)
    - Environment markers: ``package==version; python_version >= "3.8"``
    - Extras: ``package[extra]==version``

    Returns:
        List of (package_name, version, extras_dict) tuples.
    """
    entries: list[LockEntry] = []

    if not path.is_file():
        return entries

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return entries

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Strip inline comments
        if " #" in line:
            line = line[: line.index(" #")].strip()
        if "  #" in line:
            line = line[: line.index("  #")].strip()

        # Strip environment markers (semicolon)
        # e.g., "package==1.0; python_version >= '3.8'"
        marker = ""
        if ";" in line:
            line, marker = line.split(";", 1)
            marker = marker.strip()

        # Parse version specifier FIRST, then strip extras from the name
        extras_list: list[str] = []
        version = ""
        specifier = ""
        raw_line = line

        for sep in ("===", ">=", "<=", "!=", "~=", "==", ">", "<"):
            if sep in raw_line:
                name_part, version = raw_line.split(sep, 1)
                name_part = name_part.strip()
                version = version.strip()
                specifier = sep
                break
        else:
            name_part = raw_line.strip()

        # Strip extras like package[extra1,extra2] from name_part
        bracket_match = re.search(r"\[([^\]]+)\]", name_part)
        if bracket_match:
            extras_str = bracket_match.group(1)
            extras_list = [e.strip() for e in extras_str.split(",")]
            name_part = name_part[: bracket_match.start()].strip()

        if name_part:
            entries.append((
                name_part,
                version if version else "*",
                {"extras": extras_list, "marker": marker, "specifier": specifier},
            ))

    return entries


# ── Poetry.lock parser ─────────────────────────────────────────────────


def parse_poetry_lock(path: Path) -> list[LockEntry]:
    """Parse a ``poetry.lock`` file (TOML format).

    Poetry lockfiles are structured TOML with ``[[package]]`` entries:

    .. code-block:: toml

        [[package]]
        name = "requests"
        version = "2.31.0"
        description = "Python HTTP for Humans."
        category = "main"
        optional = false
        python-versions = ">=3.7"

    Returns:
        List of (package_name, version, extras_dict) tuples.
    """
    entries: list[LockEntry] = []

    if not path.is_file():
        return entries

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            logger.warning("tomllib/tomli not available — cannot parse poetry.lock")
            return entries

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        logger.debug("Failed to parse poetry.lock at %s", path)
        return entries

    for package in data.get("package", []):
        name = package.get("name", "")
        version = package.get("version", "")
        if name and version:
            extras: dict = {
                "category": package.get("category", ""),
                "optional": package.get("optional", False),
                "python-versions": package.get("python-versions", ""),
            }
            entries.append((name, version, extras))

    return entries


# ── uv.lock parser (PEP 751 / uv format) ──────────────────────────────


def parse_uv_lock(path: Path) -> list[LockEntry]:
    """Parse a ``uv.lock`` file (uv's native lockfile, TOML format).

    uv lockfiles contain hash arrays and wheel metadata per package:

    .. code-block:: toml

        [[distribution]]
        name = "requests"
        version = "2.31.0"
        source = "registry+https://pypi.org/simple"
        wheels = [...]
        sdist = {...}

    Returns:
        List of (package_name, version, extras_dict) tuples.
    """
    entries: list[LockEntry] = []

    if not path.is_file():
        return entries

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            logger.warning("tomllib/tomli not available — cannot parse uv.lock")
            return entries

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        logger.debug("Failed to parse uv.lock at %s", path)
        return entries

    for dist in data.get("distribution", []):
        name = dist.get("name", "")
        version = dist.get("version", "")
        if name and version:
            extras: dict = {
                "source": dist.get("source", ""),
            }
            entries.append((name, version, extras))

    return entries


# ── Auto-detect and parse ─────────────────────────────────────────────


def parse_pypi_lockfile(path: Path) -> list[LockEntry] | None:
    """Auto-detect lockfile format and parse accordingly.

    Inspects the filename to choose the parser:
    - ``requirements.txt``, ``requirements-dev.txt``, ``*-requirements.txt`` → pip format
    - ``poetry.lock`` → Poetry format
    - ``uv.lock`` → uv format

    Returns:
        List of entries if parsed successfully, None if format unknown.
    """
    if not path.is_file():
        return None

    name = path.name

    if name in ("poetry.lock",):
        return parse_poetry_lock(path)
    if name in ("uv.lock",):
        return parse_uv_lock(path)
    if name in ("requirements.txt",) or name.endswith("-requirements.txt") or name == "Pipfile.lock":
        return parse_requirements_txt(path)

    # Fallback: try all parsers and return the first that yields results
    for parser in (parse_poetry_lock, parse_uv_lock):
        try:
            result = parser(path)
            if result:
                return result
        except Exception:
            continue

    return None