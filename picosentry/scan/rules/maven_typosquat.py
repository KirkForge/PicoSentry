"""
L2-MAVEN-TYPO-001: Maven artifact typosquatting detection.

Flags Java/Gradle dependencies whose artifact IDs are within edit distance <=2
of popular Maven artifacts. Attackers register similar-looking artifact IDs
on Maven Central to trick developers into importing malicious code.

Pure function: (target_path, corpus_dir) -> List[Finding]

Artifact IDs in Maven are simple identifiers (like ``junit-jupiter``, ``spring-core``),
compared directly against the corpus. Group IDs are ignored for typosquat matching.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .maven_utils import (
    detect_maven_project,
    get_maven_dep_identifiers,
    parse_pom_xml,
    parse_gradle_build,
)
from .typosquat_utils import (
    BUILTIN_MAVEN_TOP_100,
    check_typosquat,
    load_corpus_for_ecosystem,
    typosquat_severity_confidence,
)

logger = logging.getLogger("picosentry.maven_typosquat")

__all__ = ["detect_maven_typosquat"]

# Known legitimate artifact ID patterns to skip (avoid false positives)
KNOWN_LEGITIMATE_MAVEN: frozenset[str] = frozenset({
    "api", "core", "client", "server", "common", "util",
    "utils", "annotations", "model", "dto", "service",
    "dao", "impl", "shared", "parent", "starter", "boot",
    "cloud", "data", "jpa", "security", "web", "config",
    "support", "base", "abstract", "spi",
})


def detect_maven_typosquat(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect Maven artifact typosquatting — artifact IDs close to popular packages.
    No network calls. Pure filesystem + corpus scan.
    """
    findings: list[Finding] = []

    if not detect_maven_project(target):
        return findings

    corpus = load_corpus_for_ecosystem(corpus_dir, "maven", BUILTIN_MAVEN_TOP_100)

    # Collect all dependency artifact IDs
    all_deps: set[str] = set()

    pom_data = parse_pom_xml(target)
    if pom_data:
        all_deps.update(get_maven_dep_identifiers(pom_data))

    gradle_data = parse_gradle_build(target)
    if gradle_data:
        all_deps.update(get_maven_dep_identifiers(gradle_data))

    for dep_name in sorted(all_deps):
        if not dep_name or dep_name in KNOWN_LEGITIMATE_MAVEN:
            continue

        # Skip if the artifact ID is itself a known popular package — it's the real thing
        if dep_name in corpus:
            continue

        close_matches = check_typosquat(dep_name, corpus)
        if close_matches:
            best_match, best_dist = close_matches[0]
            severity, confidence = typosquat_severity_confidence(dep_name, best_match, best_dist)
            source_file = "pom.xml" if pom_data else "build.gradle"
            findings.append(
                Finding(
                    rule_id="L2-MAVEN-TYPO-001",
                    severity=severity,
                    confidence=confidence,
                    package=dep_name,
                    file=str(target / source_file),
                    message=(
                        f"Artifact '{dep_name}' may be a typosquat "
                        f"of popular package '{best_match}'"
                    ),
                    evidence=f"edit_distance({dep_name}, {best_match}) = {best_dist}",
                    remediation=(
                        f"Verify that '{dep_name}' is the intended artifact, "
                        f"not a misspelling of '{best_match}'. "
                        "Check the groupId and artifact source before importing."
                    ),
                    references=[
                        "https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4",
                        "https://maven.apache.org/guides/introduction/introduction-to-the-pom.html",
                    ],
                    ecosystem="maven",
                )
            )

    return findings