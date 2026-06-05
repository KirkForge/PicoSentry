"""
PyPI-specific iteration and parsing utilities.

Analogues of ``iter_node_modules()`` and related functions from utils.py
but for the Python package ecosystem.

Provides:
- ``iter_site_packages()`` — walk site-packages directories for installed package metadata
- ``extract_metadata()`` — parse METADATA/PKG-INFO files
- ``load_pyproject_toml()`` — load Python project metadata
- ``get_python_dep_names()`` — extract dependency names from project metadata
"""

from __future__ import annotations

import configparser
import email
import logging
import re
from pathlib import Path

logger = logging.getLogger("picosentry.pypi_utils")

# ── Site-packages iteration ──────────────────────────────────────────────


def iter_site_packages(target: Path):
    """Iterate over installed packages in Python site-packages directories.

    Looks for ``site-packages`` directories under common Python virtualenv
    locations within ``target``. Yields ``(metadata_path, pkg_data)`` tuples
    where ``pkg_data`` is a dict with ``name``, ``version``, ``summary``.

    Supports:
    - Standard ``.venv/lib/python*/site-packages/`` layout
    - Editable installs (``*.egg-info`` and ``*.dist-info`` directories)
    - Flat site-packages (no virtualenv, system site-packages)

    Yields:
        Tuple of (Path, dict) where dict contains package metadata.
    """
    visited_names: set[str] = set()

    for site_dir in _find_site_packages_dirs(target):
        yield from _walk_site_packages(site_dir, visited_names)


def _find_site_packages_dirs(target: Path) -> list[Path]:
    """Find all site-packages directories under target.

    Searches for:
    - ``target/.venv/lib/python*/site-packages/``
    - ``target/venv/lib/python*/site-packages/``
    - ``target/.tox/*/lib/python*/site-packages/``
    - ``target/lib/python*/site-packages/`` (Pipenv style)
    - ``.python*`` style virtualenvs
    """
    found: list[Path] = []

    # Common virtualenv layouts
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

    # Also check for a direct site-packages hit (unusual but possible)
    direct = target / "site-packages"
    if direct.is_dir() and direct not in found:
        found.append(direct)

    return found


def _walk_site_packages(site_dir: Path, visited_names: set[str]):
    """Walk a single site-packages directory and yield installed packages."""
    if not site_dir.is_dir():
        return

    for child in sorted(site_dir.iterdir()):
        if not child.is_dir() or child.name.startswith(".") or child.name == "__pycache__":
            continue

        if child.name.endswith(".dist-info"):
            # Standard installed package: foo-1.0.0.dist-info/
            pkg_name = _parse_dist_info_name(child.name)
            if pkg_name and pkg_name not in visited_names:
                metadata = _read_dist_metadata(child)
                if metadata:
                    visited_names.add(pkg_name)
                    yield child, metadata

        elif child.name.endswith(".egg-info"):
            # Editable/setuptools install: foo.egg-info/
            pkg_name = _parse_egg_info_name(child.name)
            if pkg_name and pkg_name not in visited_names:
                metadata = _read_egg_info(child)
                if metadata:
                    visited_names.add(pkg_name)
                    yield child, metadata

        # Also check for .egg-link files (editable installs pointing elsewhere)
        for egg_link in site_dir.glob("*.egg-link"):
            if egg_link.is_file():
                try:
                    link_target = Path(egg_link.read_text(encoding="utf-8").strip())
                    if link_target.is_dir():
                        # Try to find the actual package setup dir
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
    """Parse package name from a ``.dist-info`` directory name.

    Standard format: ``PackageName-1.0.0.dist-info``
    Returns the package name portion (with hyphens/underscores preserved).
    """
    if not dirname.endswith(".dist-info"):
        return None
    base = dirname[: -len(".dist-info")]
    # Remove version: package name is everything before the last segment
    # that starts with a digit or 'v'
    parts = base.split("-")
    if len(parts) >= 2:
        # The version typically starts with a digit
        for i, part in enumerate(parts):
            if part and (part[0].isdigit() or part.startswith("v")):
                return "-".join(parts[:i])
        # Fallback: assume last part is version
        return "-".join(parts[:-1])
    return base


def _parse_egg_info_name(dirname: str) -> str | None:
    """Parse package name from an ``.egg-info`` directory name.

    Format: ``PackageName-1.0.0-py3.12.egg-info``
    Returns the package name portion.
    """
    if not dirname.endswith(".egg-info"):
        return None
    base = dirname[: -len(".egg-info")]
    # Remove trailing Python version suffix like -py3.12 if present
    base = re.sub(r"-py\d+(?:\.\d+)?$", "", base)
    parts = base.split("-")
    if len(parts) >= 2:
        for i, part in enumerate(parts):
            if part and (part[0].isdigit() or part.startswith("v")):
                return "-".join(parts[:i])
        return "-".join(parts[:-1])
    return base


# ── Metadata parsing ────────────────────────────────────────────────────


def extract_metadata(path: Path) -> dict | None:
    """Extract package metadata from a METADATA or PKG-INFO file.

    Uses the email-compatible RFC 822 format used by Python packaging.
    Returns a dict with ``name``, ``version``, ``summary``, ``requires_dist``,
    and ``requires_python`` if available.
    """
    if not path.is_file():
        return None

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    # METADATA is in RFC 822-style email format
    try:
        msg = email.message_from_string(content)
    except Exception:
        return None

    name = msg.get("Name", "")
    version = msg.get("Version", "")
    if not name or not version:
        return None

    # Collect requires_dist (dependencies)
    requires_dist: list[str] = []
    raw = msg.get_all("Requires-Dist", [])
    for line in raw:
        if line:
            requires_dist.append(line)

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
    """Read METADATA file from a ``.dist-info`` directory."""
    metadata_file = dist_dir / "METADATA"
    if metadata_file.is_file():
        return extract_metadata(metadata_file)
    return None


def _read_egg_info(egg_dir: Path) -> dict | None:
    """Read PKG-INFO file from an ``.egg-info`` directory."""
    pkg_info = egg_dir / "PKG-INFO"
    if pkg_info.is_file():
        return extract_metadata(pkg_info)
    return None


# ── pyproject.toml / setup.cfg parsing ──────────────────────────────────


def load_pyproject_toml(target: Path) -> dict | None:
    """Load Python project metadata from ``pyproject.toml``.

    Reads the ``[project]`` section for name, version, dependencies.
    Returns None if the file doesn't exist or is unparseable.
    """

    pyproject = target / "pyproject.toml"
    if not pyproject.is_file():
        return None

    try:
        # Use tomllib (Python 3.11+) or tomli fallback
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
    """Extract dependency names from Python project metadata.

    Works with both:
    - A dict from ``extract_metadata()`` (``requires_dist`` field)
    - A parsed ``pyproject.toml`` dict (``[project]`` section with ``dependencies``)
    - A ``setup.cfg`` dict (``[options]`` section with ``install_requires``)

    Returns a set of package names (without version specifiers).
    """
    names: set[str] = set()

    # Format from extract_metadata() via METADATA
    requires_dist = project_data.get("requires_dist") or project_data.get("Requires-Dist")
    if isinstance(requires_dist, list):
        for req in requires_dist:
            name = _extract_pip_package_name(str(req))
            if name:
                names.add(name)

    # Format from pyproject.toml [project]dependencies or [project.optional-dependencies]
    deps = project_data.get("dependencies", [])
    if isinstance(deps, list):
        for req in deps:
            name = _extract_pip_package_name(str(req))
            if name:
                names.add(name)

    # Optional dependencies
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
    """Extract package name from a pip-style requirement string.

    Handles formats:
    - ``requests>=2.0.0`` → ``requests``
    - ``requests[security]>=2.0.0`` → ``requests``
    - ``git+https://...`` → None (skip VCS URLs)
    - ``-r requirements.txt`` → None (skip references)
    """
    req = req.strip()
    if not req:
        return None

    # Skip VCS URLs and file paths
    if req.startswith(("git+", "hg+", "svn+", "bzr+", "http://", "https://", "ftp://", "-r ", "-c ")):
        return None

    # Skip environment markers-only lines
    if req.startswith(";"):
        return None

    # Strip extras like [security]
    name_part = re.split(r"\s*\[\s*", req, maxsplit=1)[0]

    # Take everything before the first version specifier character
    name_part = re.split(r"[><=~!;\n]", name_part, maxsplit=1)[0]

    # Strip whitespace
    name_part = name_part.strip()

    # Skip empty or markers-only
    if not name_part or name_part.startswith(";"):
        return None

    return name_part


# ── setup.py / setup.cfg (legacy) ──────────────────────────────────────


def parse_setup_cfg(target: Path) -> dict | None:
    """Parse ``setup.cfg`` for dependency information.

    Returns a dict with ``install_requires``, ``tests_require``,
    and ``extras_require`` sections if present.
    Returns None if the file doesn't exist or is unparseable.
    """
    setup_cfg = target / "setup.cfg"
    if not setup_cfg.is_file():
        return None

    try:
        config = configparser.ConfigParser()
        config.read_string(setup_cfg.read_text(encoding="utf-8"))
    except Exception:
        return None

    result: dict = {}

    if config.has_section("options"):
        options = dict(config["options"])
        install_requires = options.get("install_requires", "")
        if install_requires:
            result["install_requires"] = [
                line.strip() for line in install_requires.splitlines() if line.strip() and not line.strip().startswith("#")
            ]

    return result


# ── Requirements file parsing (pip freeze style) ───────────────────────


def parse_requirements_file(requirements_path: Path) -> list[tuple[str, str]]:
    """Parse a requirements.txt / pip-freeze style file.

    Returns list of ``(package_name, version_spec)`` tuples.
    Version spec is the full constraint string (e.g. ``>=1.0.0,<2.0.0``)
    or empty string if no version constraint.

    Handles:
    - ``name==version``
    - ``name>=version``
    - ``name`` (no version)
    - ``# comments``
    - ``-r other-file`` (skipped, no recursion)
    """
    results: list[tuple[str, str]] = []

    if not requirements_path.is_file():
        return results

    try:
        lines = requirements_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return results

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Strip inline comments
        if " #" in line:
            line = line[: line.index(" #")].strip()
        if "  #" in line:
            line = line[: line.index("  #")].strip()

        # Skip options
        if line.startswith("--"):
            continue

        # Extract name and version spec
        name = _extract_pip_package_name(line)
        if not name:
            continue

        # Get the version part (everything after name)
        version_spec = line[len(name) :].strip()
        # Strip extras from version spec if they were in the original
        if "[" in name and "]" in line:
            name[name.index("[") : line.index("]") + 1]
            name = name[: name.index("[")]

        results.append((name, version_spec))

    return results


# ── Package detection ──────────────────────────────────────────────────


def detect_pypi_project(target: Path) -> bool:
    """Check if the target directory contains a Python project.

    Returns True if any of these indicator files exist:
    - pyproject.toml
    - setup.py
    - setup.cfg
    - requirements.txt
    - Pipfile
    - poetry.lock
    - uv.lock
    - .venv/ directory
    """
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

    # Check for .venv virtualenv
    return bool((target / ".venv").is_dir())
