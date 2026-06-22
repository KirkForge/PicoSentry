from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger("picosentry.pypi_lock_parser")


LockEntry = tuple[str, str, dict]


def parse_requirements_txt(path: Path) -> list[LockEntry]:
    entries: list[LockEntry] = []

    if not path.is_file():
        return entries

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return entries

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "-")):
            continue

        if " #" in line:
            line = line[: line.index(" #")].strip()
        if "  #" in line:
            line = line[: line.index("  #")].strip()

        marker = ""
        if ";" in line:
            line, marker = line.split(";", 1)
            marker = marker.strip()

        extras_list: list[str] = []
        version = ""
        specifier = ""

        for sep in ("===", ">=", "<=", "!=", "~=", "==", ">", "<"):
            if sep in line:
                name_part, version = raw_line.split(sep, 1)
                name_part = name_part.strip()
                version = version.strip()
                specifier = sep
                break
        else:
            name_part = raw_line.strip()

        bracket_match = re.search(r"\[([^\]]+)\]", name_part)
        if bracket_match:
            extras_str = bracket_match.group(1)
            extras_list = [e.strip() for e in extras_str.split(",")]
            name_part = name_part[: bracket_match.start()].strip()

        if name_part:
            entries.append(
                (
                    name_part,
                    version or "*",
                    {"extras": extras_list, "marker": marker, "specifier": specifier},
                )
            )

    return entries


def parse_poetry_lock(path: Path) -> list[LockEntry]:
    entries: list[LockEntry] = []

    if not path.is_file():
        return entries

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            logger.warning("tomllib/tomli not available — cannot parse poetry.lock")
            return entries

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        logger.warning("Skipping poetry.lock at %s due to parse error: %s", path, exc)
        return entries
    except OSError as exc:
        logger.warning("Could not read poetry.lock at %s: %s", path, exc)
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


def parse_uv_lock(path: Path) -> list[LockEntry]:
    entries: list[LockEntry] = []

    if not path.is_file():
        return entries

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            logger.warning("tomllib/tomli not available — cannot parse uv.lock")
            return entries

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        logger.warning("Skipping uv.lock at %s due to parse error: %s", path, exc)
        return entries
    except OSError as exc:
        logger.warning("Could not read uv.lock at %s: %s", path, exc)
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
