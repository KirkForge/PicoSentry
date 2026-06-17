
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

    for line in text.splitlines():
        line = line.strip()
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


def parse_pypi_lockfile(path: Path) -> list[LockEntry] | None:
    if not path.is_file():
        return None

    name = path.name

    if name in ("poetry.lock",):
        return parse_poetry_lock(path)
    if name in ("uv.lock",):
        return parse_uv_lock(path)
    if name in ("requirements.txt",) or name.endswith("-requirements.txt") or name == "Pipfile.lock":
        return parse_requirements_txt(path)


    for parser in (parse_poetry_lock, parse_uv_lock):
        try:
            result = parser(path)
            if result:
                return result
        except Exception:
            continue

    return None
