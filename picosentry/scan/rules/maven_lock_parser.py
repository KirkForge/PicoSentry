"""
Maven lockfile-parsing wrapper — dispatches by filename to the appropriate parser.

Analogues of ``cargo_lock_parser.py`` but for the Maven ecosystem.
Maven doesn't have a universal lockfile; we treat pom.xml and build.gradle
as the dependency source and return their declared dependencies.
"""

from __future__ import annotations

from pathlib import Path

from .maven_utils import parse_gradle_build, parse_pom_xml


def parse_maven_lockfile(path: Path) -> list[tuple[str, str, str]]:
    """Auto-detect and parse a Maven build file by filename.

    Dispatches based on file name:
    - ``pom.xml`` → list of (artifact_id, version, "pom.xml")
    - ``build.gradle`` or ``build.gradle.kts`` → list of (artifact_id, version, "build.gradle")

    Returns list of (dependency_name, version, source) tuples.
    Returns empty list if the file is not recognized or can't be parsed.
    """
    name = path.name

    if name == "pom.xml":
        return parse_pom_xml_for_lock(path)
    if name in ("build.gradle", "build.gradle.kts"):
        return parse_gradle_for_lock(path)

    return []


def parse_pom_xml_for_lock(path: Path) -> list[tuple[str, str, str]]:
    """Parse a pom.xml as a "lockfile" and return (artifact_id, version, source) tuples.

    Returns dependency entries from the <dependencies> section.
    """
    pom_data = parse_pom_xml(path.parent)
    if pom_data is None:
        return []

    results: list[tuple[str, str, str]] = []
    for dep in pom_data.get("dependencies", []):
        artifact_id = dep[1]
        version = dep[2] if dep[2] else ""
        if artifact_id:
            results.append((artifact_id, version, "pom.xml"))

    return results


def parse_gradle_for_lock(path: Path) -> list[tuple[str, str, str]]:
    """Parse a build.gradle as a "lockfile" and return (artifact_id, version, source) tuples."""
    gradle_data = parse_gradle_build(path.parent)
    if gradle_data is None:
        return []

    results: list[tuple[str, str, str]] = []
    for dep in gradle_data.get("dependencies", []):
        # dep is (group, artifact, version, configuration)
        artifact = dep[1]
        version = dep[2] if dep[2] else ""
        if artifact:
            results.append((artifact, version, "build.gradle"))

    return results
