"""
L2-PYPI-TYPO-001: PyPI typosquatting detection.

Flags packages whose names are within edit distance <=2 of popular
PyPI packages. Attackers register misspelled names to trick developers
into installing malicious code.

Pure function: (target_path, corpus_dir) -> List[Finding]

Follows the same pattern as npm typosquat but uses the PyPI corpus.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .pypi_utils import (
    detect_pypi_project,
    get_python_dep_names,
    iter_site_packages,
    load_pyproject_toml,
    parse_requirements_file,
)
from .typosquat_utils import (
    BUILTIN_PYPI_TOP_100,
    check_typosquat,
    load_corpus_for_ecosystem,
    typosquat_severity_confidence,
)

logger = logging.getLogger("picosentry.pypi_typosquat")

__all__ = ["detect_pypi_typosquat"]

# Known legitimate packages that are near popular names
KNOWN_LEGITIMATE_PYPI: frozenset[str] = frozenset({
    "ruamel-yaml", "python-dateutil", "typing-extensions",
    "importlib-metadata", "importlib-resources", "pkgutil-resolve-name",
})


def detect_pypi_typosquat(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect PyPI typosquatting — package names close to popular packages.
    No network calls. Pure filesystem + corpus scan.
    """
    findings: list[Finding] = []

    if not detect_pypi_project(target):
        return findings

    corpus = load_corpus_for_ecosystem(corpus_dir, "pypi", BUILTIN_PYPI_TOP_100)

    # Collect all dependency names from project metadata
    all_deps: set[str] = set()

    # Check pyproject.toml
    project_data = load_pyproject_toml(target)
    if project_data:
        project_section = project_data.get("project", project_data)
        all_deps.update(get_python_dep_names(project_section))

    # Check requirements.txt
    for req_file in ("requirements.txt", "requirements-dev.txt"):
        req_path = target / req_file
        if req_path.is_file():
            for name, _version in parse_requirements_file(req_path):
                all_deps.add(name)

    # Check installed site-packages
    for _meta_path, metadata in iter_site_packages(target):
        all_deps.update(get_python_dep_names(metadata))

    # Check root package name (if the project itself is a malicious typosquat)
    if project_data:
        project_section = project_data.get("project", project_data)
        pkg_name = project_section.get("name", "")
        if isinstance(pkg_name, str) and pkg_name:
            all_deps.add(pkg_name)

    for dep_name in sorted(all_deps):
        if not dep_name or dep_name in corpus or dep_name in KNOWN_LEGITIMATE_PYPI:
            continue

        close_matches = check_typosquat(dep_name, corpus)
        if close_matches:
            best_match, best_dist = close_matches[0]
            severity, confidence = typosquat_severity_confidence(dep_name, best_match, best_dist)
            findings.append(
                Finding(
                    rule_id="L2-PYPI-TYPO-001",
                    severity=severity,
                    confidence=confidence,
                    package=dep_name,
                    file=str(target / "pyproject.toml") if (target / "pyproject.toml").exists() else str(target),
                    message=(
                        f"PyPI package '{dep_name}' may be a typosquat of popular package(s): {', '.join(m[0] for m in close_matches)}"
                    ),
                    evidence=f"edit_distance({dep_name}, {best_match}) = {best_dist}",
                    remediation=(
                        f"Verify that '{dep_name}' is the intended package, "
                        f"not a misspelling of '{best_match}'. "
                        "Check the PyPI page and author before installing."
                    ),
                    references=[
                        "https://blog.npmjs.org/post/186451959906/typosquatting-on-npm",
                        "https://snyk.io/blog/typosquatting-attacks/",
                    ],
                    ecosystem="pypi",
                )
            )

    return findings