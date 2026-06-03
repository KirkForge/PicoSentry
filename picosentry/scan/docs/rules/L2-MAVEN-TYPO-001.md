# L2-MAVEN-TYPO-001: Maven Artifact Typosquatting

**Severity:** HIGH  
**Category:** typosquat  
**Ecosystem:** maven  

## Description

Detects Maven artifact IDs declared in pom.xml or build.gradle whose names are
within edit distance ≤2 of popular Maven packages. Attackers register
misspelled artifact IDs on Maven Central to trick developers into importing
malicious code.

## Detection Method

The rule extracts all artifact IDs from `<dependencies>` sections in pom.xml
and `dependencies {}` blocks in build.gradle (Groovy DSL), then compares each
name against the corpus of top Maven artifact IDs using Levenshtein edit
distance.

## Mitigation

- Double-check artifact IDs before adding them to your pom.xml or build.gradle.
- Verify the groupId and artifact source before importing.
- Use a private repository for internal artifacts to avoid confusion.

## References

- [Dependency Confusion](https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4)
- [Maven POM Introduction](https://maven.apache.org/guides/introduction/introduction-to-the-pom.html)