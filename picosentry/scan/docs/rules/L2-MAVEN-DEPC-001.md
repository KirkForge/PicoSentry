# L2-MAVEN-DEPC-001: Maven Dependency Confusion

**Severity:** CRITICAL  
**Category:** dependency  
**Ecosystem:** maven  

## Description

Detects internal-looking artifact IDs or group IDs declared in pom.xml or
build.gradle without a private repository configuration. Attackers can
register internal-looking artifact IDs on Maven Central, causing the build to
resolve the public malicious version instead of the intended private one.

## Detection Method

The rule checks each dependency's groupId and artifactId for patterns that
suggest internal/private usage (e.g., `internal-*`, `private-*`, single-segment
group IDs). If no private repository is configured (via custom `<repositories>`
in pom.xml, `repositories {}` in Gradle, or settings.xml), the dependency is
flagged.

## Mitigation

- Configure a private repository via `<repositories>` in pom.xml.
- Use settings.xml to define private repository credentials.
- Use dependency management to pin versions for internal artifacts.

## References

- [Dependency Confusion](https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4)
- [Maven Settings Reference](https://maven.apache.org/settings.html#Servers)