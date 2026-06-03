"""
L2-PYPI-DEPC-001: PyPI dependency confusion detection.

Flags internal/private package names that could be squatted on the public
PyPI registry. Attackers register internal-looking package names on PyPI
to inject malicious code when install resolution picks the public package.

Pure function: (target_path, corpus_dir) -> List[Finding]

Follows the same pattern as npm dep_confusion but adapted for Python's
pip/pypi.conf / pip.conf / .pypirc configuration files.
"""

from __future__ import annotations

import configparser
import logging
import re
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .pypi_utils import (
    detect_pypi_project,
    get_python_dep_names,
    load_pyproject_toml,
    parse_requirements_file,
)

logger = logging.getLogger("picosentry.pypi_dep_confusion")

__all__ = ["detect_pypi_dep_confusion"]

# Well-known placeholder names that indicate internal/private packages
_DEFAULT_INTERNAL_PATTERNS = [
    r"^internal-",
    r"^private-",
    r"^my-",
    r"^acme-",
    r"^company-",
    r"^org-",
    r"^corp-",
]


def _has_private_index(target: Path) -> bool:
    """Check if a private PyPI index is configured.

    Looks for:
    - ``pip.conf`` / ``pip.ini`` with ``index-url`` pointing to a private registry
    - ``pypirc`` with private repository configuration
    - ``pyproject.toml`` with ``[[tool.pip.index]]`` or ``[tool.poetry.source]``
    """
    # Check pip.conf
    pip_conf_locations = [
        target / "pip.conf",
        target / "pip.ini",
        target / ".pip" / "pip.conf",
    ]
    for pip_conf in pip_conf_locations:
        if pip_conf.is_file():
            try:
                content = pip_conf.read_text(encoding="utf-8", errors="replace")
                if "index-url" in content:
                    # Check if the URL is NOT pypi.org
                    for line in content.splitlines():
                        if "index-url" in line and "pypi.org" not in line:
                            return True
            except OSError:
                continue

    # Check .pypirc
    pypirc = target / ".pypirc"
    if pypirc.is_file():
        try:
            config = configparser.ConfigParser()
            config.read_string(pypirc.read_text(encoding="utf-8"))
            for section in config.sections():
                if section != "distutils" and config.has_option(section, "repository"):
                    repo_url = config.get(section, "repository")
                    if "pypi.org" not in repo_url:
                        return True
        except Exception:
            pass

    # Check pyproject.toml for [tool.poetry.source]
    project_data = load_pyproject_toml(target)
    if project_data:
        poetry_sources = project_data.get("tool", {}).get("poetry", {}).get("source", [])
        if isinstance(poetry_sources, list):
            for source in poetry_sources:
                url = source.get("url", "")
                if url and "pypi.org" not in url and "pypi.python.org" not in url:
                    return True

    return False


def _looks_internal(package_name: str) -> bool:
    """Heuristic check if a package name looks like an internal/private name."""
    for pattern in _DEFAULT_INTERNAL_PATTERNS:
        if re.match(pattern, package_name, re.IGNORECASE):
            return True
    return False


def detect_pypi_dep_confusion(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect PyPI dependency confusion vectors.
    No network calls. Pure filesystem scan.
    """
    findings: list[Finding] = []

    if not detect_pypi_project(target):
        return findings

    # Collect all dependency names
    all_deps: set[str] = set()

    project_data = load_pyproject_toml(target)
    if project_data:
        project_section = project_data.get("project", project_data)
        all_deps.update(get_python_dep_names(project_section))

    for req_file in ("requirements.txt", "requirements-dev.txt"):
        req_path = target / req_file
        if req_path.is_file():
            for name, _version in parse_requirements_file(req_path):
                all_deps.add(name)

    if not all_deps:
        return findings

    has_private = _has_private_index(target)

    for dep_name in sorted(all_deps):
        is_internal = _looks_internal(dep_name)

        # If no private index is configured, warn about internal-looking deps
        if is_internal and not has_private:
            findings.append(
                Finding(
                    rule_id="L2-PYPI-DEPC-001",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    package=dep_name,
                    file=str(target / "pyproject.toml") if (target / "pyproject.toml").exists() else str(target),
                    message=(
                        f"Internal-looking dependency '{dep_name}' declared "
                        "without private PyPI index configuration"
                    ),
                    evidence=f"dependency: {dep_name}",
                    remediation=(
                        f"Add a private index URL in pip.conf or pyproject.toml "
                        f"for '{dep_name}' to prevent pip from resolving it from public PyPI."
                    ),
                    references=[
                        "https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4",
                        "https://pip.pypa.io/en/stable/topics/configuration/",
                    ],
                    ecosystem="pypi",
                )
            )

    return findings