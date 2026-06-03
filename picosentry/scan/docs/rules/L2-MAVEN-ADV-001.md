# L2-MAVEN-ADV-001: Maven Advisory Vulnerability Check

**Severity:** HIGH  
**Category:** vulnerability  
**Ecosystem:** maven  

## Description

Checks Maven/Gradle dependencies against a local OSV-format advisory database.
Flags artifacts with known CVEs or security advisories from the Maven ecosystem.

## Detection Method

The rule extracts all dependency coordinates (`groupId:artifactId` and version)
from pom.xml and build.gradle, then checks each against the advisory database.
It uses the `groupId:artifactId` as the package identifier with "Maven" as the
OSV ecosystem.

## Mitigation

- Update vulnerable dependencies to the fixed version specified in the advisory.
- Review the advisory details for impact assessment.
- Run `picosentry update` to refresh the advisory database regularly.

## References

- [OSV Database](https://osv.dev/)
- [Maven Security Advisories](https://maven.apache.org/security/)