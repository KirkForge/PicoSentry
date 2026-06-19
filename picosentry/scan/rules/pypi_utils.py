from __future__ import annotations

import email
import logging
import re
from pathlib import Path

logger = logging.getLogger("picosentry.pypi_utils")


def iter_site_packages(target: Path):
    visited_names: set[str] = set()

    for site_dir in _find_site_packages_dirs(target):
        yield from _walk_site_packages(site_dir, visited_names)


def _find_site_packages_dirs(target: Path) -> list[Path]:
    found: list[Path] = []

    patterns = [
        ".venv/lib/python*/site-packages",
        "venv/lib/python*/site-packages",
        ".tox/*/lib/python*/site-packages",
        "lib/python*/site-packages",
        ".python*/lib/python*/site-packages",
        "__pypackages__/*/lib/python*/site-packages",  # PEP 582
    ]

    for pattern in patterns:
        for p in target.glob(pattern):
            if p.is_dir() and p not in found:
                found.append(p)

    direct = target / "site-packages"
    if direct.is_dir() and direct not in found:
        found.append(direct)

    return found


def _walk_site_packages(site_dir: Path, visited_names: set[str]):
    if not site_dir.is_dir():
        return

    for child in sorted(site_dir.iterdir()):
        if not child.is_dir() or child.name.startswith(".") or child.name == "__pycache__":
            continue

        if child.name.endswith(".dist-info"):
            pkg_name = _parse_dist_info_name(child.name)
            if pkg_name and pkg_name not in visited_names:
                metadata = _read_dist_metadata(child)
                if metadata:
                    visited_names.add(pkg_name)
                    yield child, metadata

        elif child.name.endswith(".egg-info"):
            pkg_name = _parse_egg_info_name(child.name)
            if pkg_name and pkg_name not in visited_names:
                metadata = _read_egg_info(child)
                if metadata:
                    visited_names.add(pkg_name)
                    yield child, metadata

        for egg_link in site_dir.glob("*.egg-link"):
            if egg_link.is_file():
                try:
                    link_target = Path(egg_link.read_text(encoding="utf-8").strip())
                    if link_target.is_dir():
                        for sub in link_target.iterdir():
                            if sub.name.endswith(".egg-info") and sub.is_dir():
                                pkg_name = _parse_egg_info_name(sub.name)
                                if pkg_name and pkg_name not in visited_names:
                                    metadata = _read_egg_info(sub)
                                    if metadata:
                                        visited_names.add(pkg_name)
                                        yield sub, metadata
                except OSError:
                    continue


def _parse_dist_info_name(dirname: str) -> str | None:
    if not dirname.endswith(".dist-info"):
        return None
    base = dirname[: -len(".dist-info")]

    parts = base.split("-")
    if len(parts) >= 2:
        for i, part in enumerate(parts):
            if part and (part[0].isdigit() or part.startswith("v")):
                return "-".join(parts[:i])

        return "-".join(parts[:-1])
    return base


def _parse_egg_info_name(dirname: str) -> str | None:
    if not dirname.endswith(".egg-info"):
        return None
    base = dirname[: -len(".egg-info")]

    base = re.sub(r"-py\d+(?:\.\d+)?$", "", base)
    parts = base.split("-")
    if len(parts) >= 2:
        for i, part in enumerate(parts):
            if part and (part[0].isdigit() or part.startswith("v")):
                return "-".join(parts[:i])
        return "-".join(parts[:-1])
    return base


def extract_metadata(path: Path) -> dict | None:
    if not path.is_file():
        return None

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    try:
        msg = email.message_from_string(content)
    except Exception:
        return None

    name = msg.get("Name", "")
    version = msg.get("Version", "")
    if not name or not version:
        return None

    raw = msg.get_all("Requires-Dist", [])
    requires_dist = [line for line in raw if line]

    return {
        "name": name,
        "version": version,
        "summary": msg.get("Summary", ""),
        "requires_python": msg.get("Requires-Python", ""),
        "requires_dist": requires_dist,
        "description": msg.get("Description", ""),
        "home_page": msg.get("Home-Page", ""),
        "author": msg.get("Author", ""),
        "author_email": msg.get("Author-email", ""),
        "license": msg.get("License", ""),
    }


def _read_dist_metadata(dist_dir: Path) -> dict | None:
    metadata_file = dist_dir / "METADATA"
    if metadata_file.is_file():
        return extract_metadata(metadata_file)
    return None


def _read_egg_info(egg_dir: Path) -> dict | None:
    pkg_info = egg_dir / "PKG-INFO"
    if pkg_info.is_file():
        return extract_metadata(pkg_info)
    return None


def load_pyproject_toml(target: Path) -> dict | None:

    pyproject = target / "pyproject.toml"
    if not pyproject.is_file():
        return None

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            logger.warning("tomllib/tomli not available — cannot parse pyproject.toml")
            return None

    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except Exception:
        return None

    return data


def get_python_dep_names(project_data: dict) -> set[str]:
    names: set[str] = set()

    requires_dist = project_data.get("requires_dist") or project_data.get("Requires-Dist")
    if isinstance(requires_dist, list):
        for req in requires_dist:
            name = _extract_pip_package_name(str(req))
            if name:
                names.add(name)

    deps = project_data.get("dependencies", [])
    if isinstance(deps, list):
        for req in deps:
            name = _extract_pip_package_name(str(req))
            if name:
                names.add(name)

    opt_deps = project_data.get("optional-dependencies", {})
    if isinstance(opt_deps, dict):
        for group_reqs in opt_deps.values():
            if isinstance(group_reqs, list):
                for req in group_reqs:
                    name = _extract_pip_package_name(str(req))
                    if name:
                        names.add(name)

    return names


def _extract_pip_package_name(req: str) -> str | None:
    req = req.strip()
    if not req:
        return None

    if req.startswith(("git+", "hg+", "svn+", "bzr+", "http://", "https://", "ftp://", "-r ", "-c ")):
        return None

    if req.startswith(";"):
        return None

    name_part = re.split(r"\s*\[\s*", req, maxsplit=1)[0]

    name_part = re.split(r"[><=~!;\n]", name_part, maxsplit=1)[0]

    name_part = name_part.strip()

    if not name_part or name_part.startswith(";"):
        return None

    return name_part


def parse_requirements_file(requirements_path: Path) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []

    if not requirements_path.is_file():
        return results

    try:
        lines = requirements_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return results

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith(("#", "-")):
            continue

        if " #" in line:
            line = line[: line.index(" #")].strip()
        if "  #" in line:
            line = line[: line.index("  #")].strip()

        if line.startswith("--"):
            continue

        name = _extract_pip_package_name(line)
        if not name:
            continue

        version_spec = line[len(name) :].strip()

        if "[" in name and "]" in line:
            name[name.index("[") : line.index("]") + 1]
            name = name[: name.index("[")]

        results.append((name, version_spec))

    return results


def detect_pypi_project(target: Path) -> bool:
    if not target.is_dir():
        return False

    indicators = [
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "requirements.txt",
        "requirements-dev.txt",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
    ]

    for indicator in indicators:
        if (target / indicator).is_file():
            return True

    return bool((target / ".venv").is_dir())
