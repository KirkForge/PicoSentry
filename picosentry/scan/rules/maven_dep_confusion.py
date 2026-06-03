"""
L2-MAVEN-DEPC-001: Maven dependency confusion detection.

Flags internal-looking groupId/artifactIds that could be squatted on Maven Central.
Attackers register internal-looking artifact IDs on public repositories
to inject malicious code when the build resolves the dependency.

Pure function: (target_path, corpus_dir) -> List[Finding]

Maven-specific considerations:
- Maven Central is the default public repository
- Private repositories use ``<repositories>`` in pom.xml or ``repositories {}`` in Gradle
- Internal-looking artifact IDs often have company-prefixed or generic names
- Group IDs with single segments (e.g. ``mycompany``) or non-public reverse domains
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .maven_utils import (
    detect_maven_project,
    detect_private_maven_repository,
    get_maven_dep_identifiers,
    parse_pom_xml,
    parse_gradle_build,
)

logger = logging.getLogger("picosentry.maven_dep_confusion")

__all__ = ["detect_maven_dep_confusion"]

# Patterns indicating internal/private artifact IDs
_DEFAULT_INTERNAL_PATTERNS = [
    r"^internal-",
    r"^private-",
    r"^my-",
    r"^acme-",
    r"^company-",
    r"^org-",
    r"^corp-",
    r"^test-",
    r"^example-",
    r"^local-",
    r"-internal$",
    r"-private$",
    r"-local$",
]

# Look for single-segment group IDs (e.g. ``mycompany``, ``internal``)
_SINGLE_SEGMENT_GROUP_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9._-]*$")

# Known public group ID prefixes (reverse domain convention)
_PUBLIC_GROUP_PREFIXES: frozenset[str] = frozenset({
    "org.springframework", "com.fasterxml", "org.apache", "com.google",
    "org.slf4j", "org.junit", "org.mockito", "org.hibernate",
    "io.netty", "io.reactivex", "io.micrometer", "io.grpc",
    "io.vertx", "io.quarkus", "io.dropwizard", "io.jsonwebtoken",
    "com.fasterxml.jackson", "com.squareup", "com.github",
    "net.bytebuddy", "net.sf", "org.jboss", "org.eclipse",
    "org.projectlombok", "org.checkerframework", "org.jetbrains",
    "com.zaxxer", "org.yaml", "org.codehaus", "org.gradle",
    "org.apache.maven", "org.apache.logging", "org.apache.commons",
    "org.apache.httpcomponents", "org.jacoco", "com.thoughtworks",
    "tech.units", "javax", "jakarta",
})

# Well-known safe artifact IDs that look internal but are real
_KNOWN_SAFE_ARTIFACTS: frozenset[str] = frozenset({
    "api", "core", "common", "util", "utils", "server", "client",
    "annotations", "parent", "boot", "starter", "data", "jpa",
    "security", "web", "model", "dto", "service", "dao", "impl",
})


def _looks_internal(group_id: str, artifact_id: str) -> bool:
    """Heuristic check if a dependency looks like an internal/private artifact.

    Checks:
    - Artifact ID matches known internal prefixes/suffixes
    - Group ID is a single segment (no dots) — uncommon for public artifacts
    - Group ID doesn't start with a known public prefix
    - Artifact ID is not in the known-safe list
    """
    if artifact_id in _KNOWN_SAFE_ARTIFACTS:
        return False

    # Check artifact ID against internal patterns
    for pattern in _DEFAULT_INTERNAL_PATTERNS:
        if re.search(pattern, artifact_id, re.IGNORECASE):
            return True

    # Single-segment group IDs (no dots) without known public prefix
    if group_id and "." not in group_id and _SINGLE_SEGMENT_GROUP_RE.match(group_id):
        return True

    # Group ID starts with a known public prefix — likely legitimate
    if group_id:
        for prefix in _PUBLIC_GROUP_PREFIXES:
            if group_id.startswith(prefix):
                return False

    return False


def detect_maven_dep_confusion(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect Maven dependency confusion vectors.
    No network calls. Pure filesystem scan.
    """
    findings: list[Finding] = []

    if not detect_maven_project(target):
        return findings

    # Collect all dependencies with their groupId and artifactId
    deps: list[tuple[str, str, str]] = []  # (group_id, artifact_id, version)

    pom_data = parse_pom_xml(target)
    if pom_data:
        for dep in pom_data.get("dependencies", []):
            # dep is (group_id, artifact_id, version, scope)
            deps.append((dep[0], dep[1], dep[2]))

    gradle_data = parse_gradle_build(target)
    if gradle_data:
        for dep in gradle_data.get("dependencies", []):
            # dep is (group, artifact, version, configuration)
            deps.append((dep[0], dep[1], dep[2]))

    if not deps:
        return findings

    has_private = detect_private_maven_repository(target)

    for group_id, artifact_id, version in sorted(deps):
        if not group_id or not artifact_id:
            continue

        is_internal = _looks_internal(group_id, artifact_id)

        if is_internal and not has_private:
            dep_ref = f"{group_id}:{artifact_id}"
            findings.append(
                Finding(
                    rule_id="L2-MAVEN-DEPC-001",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    package=dep_ref,
                    file=str(target / "pom.xml") if pom_data else str(target / "build.gradle"),
                    message=(
                        f"Internal-looking dependency '{dep_ref}' declared "
                        "without private Maven repository configuration"
                    ),
                    evidence=f"dependency: {dep_ref}",
                    remediation=(
                        f"Configure a private repository for '{dep_ref}' via "
                        "<repositories> in pom.xml, or add a custom repository "
                        "URL in build.gradle to prevent Maven from resolving it "
                        "from Maven Central."
                    ),
                    references=[
                        "https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4",
                        "https://maven.apache.org/settings.html#Servers",
                    ],
                    ecosystem="maven",
                )
            )

    return findings