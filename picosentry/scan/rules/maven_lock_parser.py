from __future__ import annotations

from pathlib import Path

from .maven_utils import parse_gradle_build, parse_pom_xml


def parse_maven_lockfile(path: Path) -> list[tuple[str, str, str]]:
    name = path.name

    if name == "pom.xml":
        return parse_pom_xml_for_lock(path)
    if name in ("build.gradle", "build.gradle.kts"):
        return parse_gradle_for_lock(path)

    return []


def parse_pom_xml_for_lock(path: Path) -> list[tuple[str, str, str]]:
    pom_data = parse_pom_xml(path.parent)
    if pom_data is None:
        return []

    results: list[tuple[str, str, str]] = []
    for dep in pom_data.get("dependencies", []):
        artifact_id = dep[1]
        version = dep[2] or ""
        if artifact_id:
            results.append((artifact_id, version, "pom.xml"))

    return results


def parse_gradle_for_lock(path: Path) -> list[tuple[str, str, str]]:
    gradle_data = parse_gradle_build(path.parent)
    if gradle_data is None:
        return []

    results: list[tuple[str, str, str]] = []
    for dep in gradle_data.get("dependencies", []):
        artifact = dep[1]
        version = dep[2] or ""
        if artifact:
            results.append((artifact, version, "build.gradle"))

    return results
