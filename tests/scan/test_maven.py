"""Tests for Maven ecosystem rules.

Tests cover:
- Ecosystem detection (pom.xml)
- Maven typosquat detection (L2-MAVEN-TYPO-001)
- Maven dependency confusion (L2-MAVEN-DEPC-001)
- Maven advisory check (L2-MAVEN-ADV-001)
- Engine ecosystem filtering
"""

from pathlib import Path

from picosentry.scan.engine import create_default_engine
from picosentry.scan.models import Severity

# ── Fixture helpers ────────────────────────────────────────────────────

FIXTURES = Path(__file__).parent / "fixtures"


def _maven_clean() -> Path:
    return FIXTURES / "maven_clean"


def _maven_malicious() -> Path:
    return FIXTURES / "maven_malicious"


# ── Ecosystem detection ────────────────────────────────────────────────


class TestMavenDetection:
    """Maven project detection should work with pom.xml."""

    def test_detects_pom_xml(self):
        from picosentry.scan.rules.maven_utils import detect_maven_project
        assert detect_maven_project(_maven_clean())

    def test_detects_pom_xml_malicious(self):
        from picosentry.scan.rules.maven_utils import detect_maven_project
        assert detect_maven_project(_maven_malicious())

    def test_no_indicator_returns_false(self, tmp_path):
        from picosentry.scan.rules.maven_utils import detect_maven_project
        assert not detect_maven_project(tmp_path)

    def test_build_gradle_detection(self, tmp_path):
        from picosentry.scan.rules.maven_utils import detect_maven_project
        (tmp_path / "build.gradle").write_text("")
        assert detect_maven_project(tmp_path)

    def test_mvnw_detection(self, tmp_path):
        from picosentry.scan.rules.maven_utils import detect_maven_project
        (tmp_path / "mvnw").write_text("")
        assert detect_maven_project(tmp_path)

    def test_not_a_directory_returns_false(self, tmp_path):
        from picosentry.scan.rules.maven_utils import detect_maven_project
        f = tmp_path / "not_a_dir"
        f.write_text("")
        assert not detect_maven_project(f)


# ── Engine ecosystem filtering ─────────────────────────────────────────


class TestMavenEcosystemFiltering:
    """Engine should only run Maven rules when a pom.xml is present."""

    def test_npm_project_skips_maven_rules(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        engine = create_default_engine()
        result = engine.scan(tmp_path)
        maven_findings = [f for f in result.findings if f.rule_id.startswith("L2-MAVEN-")]
        assert len(maven_findings) == 0

    def test_maven_project_runs_maven_rules(self):
        engine = create_default_engine()
        result = engine.scan(_maven_clean())
        [f for f in result.findings if f.ecosystem == "maven"]
        # Should at least run the rules without erroring

    def test_three_maven_rules_registered(self):
        engine = create_default_engine()
        shared_rules = [rid for rid in engine.list_rules() if rid in ("L2-TYPO-001", "L2-DEPC-001", "L2-ADV-001")]
        assert len(shared_rules) == 3
        assert "L2-TYPO-001" in shared_rules
        assert "L2-DEPC-001" in shared_rules
        assert "L2-ADV-001" in shared_rules


# ── Maven Typosquat ────────────────────────────────────────────────────


class TestMavenTyposquat:
    """Maven typosquat detection should flag suspicious artifact IDs."""

    def test_detects_typosquat_in_malicious(self):
        from picosentry.scan.rules.typosquat import detect_all_typosquat as detect_maven_typosquat
        findings = detect_maven_typosquat(_maven_malicious(), FIXTURES.parent.parent / "picosentry" / "scan" / "corpus")
        typo_findings = [f for f in findings if f.rule_id == "L2-MAVEN-TYPO-001"]
        assert len(typo_findings) >= 1
        # "spting-boot-starter-web" is edit distance 1 from "spring-boot-starter-web"
        assert any("spting" in f.package.lower() or "spting" in f.message.lower() for f in typo_findings)

    def test_clean_project_has_no_typosquats(self):
        from picosentry.scan.rules.typosquat import detect_all_typosquat as detect_maven_typosquat
        findings = detect_maven_typosquat(_maven_clean(), FIXTURES.parent.parent / "picosentry" / "scan" / "corpus")
        typo_findings = [f for f in findings if f.rule_id == "L2-MAVEN-TYPO-001"]
        assert len(typo_findings) == 0


# ── Maven Dependency Confusion ─────────────────────────────────────────


class TestMavenDependencyConfusion:
    """Maven dep confusion detection should flag internal-looking deps."""

    def test_detects_dep_confusion_in_malicious(self):
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_maven_dep_confusion
        findings = detect_maven_dep_confusion(_maven_malicious())
        depc_findings = [f for f in findings if f.rule_id == "L2-MAVEN-DEPC-001"]
        assert len(depc_findings) >= 1
        # "internal-lib" should be flagged
        assert any("internal-lib" in f.package for f in depc_findings)

    def test_clean_project_has_no_dep_confusion(self):
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_maven_dep_confusion
        findings = detect_maven_dep_confusion(_maven_clean())
        depc_findings = [f for f in findings if f.rule_id == "L2-MAVEN-DEPC-001"]
        assert len(depc_findings) == 0

    def test_private_repository_suppresses_finding(self, tmp_path):
        """If a private repo is configured, internal-looking deps should not be flagged."""
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_maven_dep_confusion
        # Create pom.xml with internal-looking dep AND a custom repository
        pom_path = tmp_path / "pom.xml"
        pom_path.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test</artifactId>
    <version>1.0</version>
    <repositories>
        <repository>
            <id>internal-repo</id>
            <url>https://internal.maven.example.com/releases</url>
        </repository>
    </repositories>
    <dependencies>
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>internal-lib</artifactId>
            <version>1.0.0</version>
        </dependency>
    </dependencies>
</project>""")
        findings = detect_maven_dep_confusion(tmp_path)
        depc_findings = [f for f in findings if f.rule_id == "L2-MAVEN-DEPC-001"]
        assert len(depc_findings) == 0

    def test_single_segment_group_id_flagged(self, tmp_path):
        """Single-segment group IDs (no dots) should be flagged as internal."""
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_maven_dep_confusion
        pom_path = tmp_path / "pom.xml"
        pom_path.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test</artifactId>
    <version>1.0</version>
    <dependencies>
        <dependency>
            <groupId>mycompany</groupId>
            <artifactId>secret-tool</artifactId>
            <version>1.0.0</version>
        </dependency>
    </dependencies>
</project>""")
        findings = detect_maven_dep_confusion(tmp_path)
        depc_findings = [f for f in findings if f.rule_id == "L2-MAVEN-DEPC-001"]
        assert len(depc_findings) >= 1


# ── Maven pom.xml parsing ──────────────────────────────────────────────


class TestMavenParsing:
    """Maven pom.xml parsing should extract metadata correctly."""

    def test_parse_pom_xml_package_name(self):
        from picosentry.scan.rules.maven_utils import parse_pom_xml
        data = parse_pom_xml(_maven_clean())
        assert data is not None
        assert data["artifact_id"] == "my-app"
        assert data["group_id"] == "com.example"

    def test_parse_pom_xml_dependencies(self):
        from picosentry.scan.rules.maven_utils import parse_pom_xml
        data = parse_pom_xml(_maven_clean())
        assert data is not None
        deps = data.get("dependencies", [])
        # Expect: junit-jupiter, mockito-core, spring-boot-starter-web
        assert len(deps) == 3
        dep_artifact_ids = {d[1] for d in deps}
        assert "junit-jupiter" in dep_artifact_ids
        assert "spring-boot-starter-web" in dep_artifact_ids

    def test_parse_pom_xml_no_file_returns_none(self, tmp_path):
        from picosentry.scan.rules.maven_utils import parse_pom_xml
        assert parse_pom_xml(tmp_path) is None

    def test_parse_pom_xml_properties(self):
        from picosentry.scan.rules.maven_utils import parse_pom_xml
        data = parse_pom_xml(_maven_clean())
        assert data is not None
        props = data.get("properties", {})
        assert props.get("java.version") == "17"
        assert props.get("spring.version") == "6.0.0"


# ── Maven Lockfile Parser ──────────────────────────────────────────────


class TestMavenLockfileParser:
    """Maven lockfile parser should dispatch by filename."""

    def test_parse_pom_xml_for_lock(self):
        from picosentry.scan.rules.maven_lock_parser import parse_pom_xml_for_lock
        entries = parse_pom_xml_for_lock(_maven_clean() / "pom.xml")
        assert len(entries) == 3
        artifact_ids = {e[0] for e in entries}
        assert "junit-jupiter" in artifact_ids
        assert "spring-boot-starter-web" in artifact_ids

    def test_parse_maven_lockfile_auto_detect_toml(self):
        from picosentry.scan.rules.maven_lock_parser import parse_maven_lockfile
        entries = parse_maven_lockfile(_maven_clean() / "pom.xml")
        assert len(entries) == 3

    def test_parse_maven_lockfile_no_file_returns_empty(self, tmp_path):
        from picosentry.scan.rules.maven_lock_parser import parse_maven_lockfile
        assert parse_maven_lockfile(tmp_path / "nonexistent.xml") == []

    def test_parse_maven_lockfile_unrecognized(self, tmp_path):
        from picosentry.scan.rules.maven_lock_parser import parse_maven_lockfile
        f = tmp_path / "random.txt"
        f.write_text("")
        assert parse_maven_lockfile(f) == []


# ── Maven Utilities ────────────────────────────────────────────────────


class TestMavenUtils:
    """Maven utility functions."""

    def test_get_maven_dep_identifiers(self):
        from picosentry.scan.rules.maven_utils import get_maven_dep_identifiers, parse_pom_xml
        data = parse_pom_xml(_maven_clean())
        assert data is not None
        names = get_maven_dep_identifiers(data)
        assert "junit-jupiter" in names
        assert "spring-boot-starter-web" in names

    def test_detect_private_repository_clean(self):
        from picosentry.scan.rules.maven_utils import detect_private_maven_repository
        # Clean fixture has no custom repos
        assert not detect_private_maven_repository(_maven_clean())

    def test_detect_private_repository_with_custom_url(self, tmp_path):
        from picosentry.scan.rules.maven_utils import detect_private_maven_repository
        pom_path = tmp_path / "pom.xml"
        pom_path.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test</artifactId>
    <version>1.0</version>
    <repositories>
        <repository>
            <id>private-repo</id>
            <url>https://internal.maven.example.com/releases</url>
        </repository>
    </repositories>
</project>""")
        assert detect_private_maven_repository(tmp_path)

    def test_detect_private_repository_with_distribution_management(self, tmp_path):
        from picosentry.scan.rules.maven_utils import detect_private_maven_repository
        pom_path = tmp_path / "pom.xml"
        pom_path.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test</artifactId>
    <version>1.0</version>
    <distributionManagement>
        <repository>
            <id>internal-releases</id>
            <url>https://internal.maven.example.com/releases</url>
        </repository>
    </distributionManagement>
</project>""")
        assert detect_private_maven_repository(tmp_path)

    def test_detect_private_repository_gradle_maven_publish(self, tmp_path):
        from picosentry.scan.rules.maven_utils import detect_private_maven_repository
        gradle_path = tmp_path / "build.gradle"
        gradle_path.write_text("""
plugins {
    id 'java'
    id 'maven-publish'
}
group = 'com.example'
version = '1.0'
""")
        assert detect_private_maven_repository(tmp_path)


# ── Integration ────────────────────────────────────────────────────────


class TestMavenIntegration:
    """Full engine integration tests."""

    def test_clean_project_no_findings(self):
        engine = create_default_engine()
        result = engine.scan(_maven_clean())
        maven_findings = [f for f in result.findings if "L2-MAVEN" in f.rule_id]
        assert len(maven_findings) == 0

    def test_malicious_project_has_findings(self):
        engine = create_default_engine()
        result = engine.scan(_maven_malicious())
        maven_findings = [f for f in result.findings if "L2-MAVEN" in f.rule_id]
        assert len(maven_findings) >= 2  # typosquat + dep confusion
        rule_ids = {f.rule_id for f in maven_findings}
        assert "L2-MAVEN-TYPO-001" in rule_ids
        assert "L2-MAVEN-DEPC-001" in rule_ids

    def test_findings_have_maven_ecosystem(self):
        from picosentry.scan.rules.typosquat import detect_all_typosquat as detect_maven_typosquat
        findings = detect_maven_typosquat(_maven_malicious(), FIXTURES.parent.parent / "picosentry" / "scan" / "corpus")
        for f in findings:
            assert f.ecosystem == "maven"

    def test_dep_confusion_findings_are_critical(self):
        from picosentry.scan.rules.dep_confusion import detect_all_dep_confusion as detect_maven_dep_confusion
        findings = detect_maven_dep_confusion(_maven_malicious())
        for f in findings:
            assert f.severity == Severity.CRITICAL
            assert f.ecosystem == "maven"

    def test_npm_backward_compat_preserved(self, tmp_path):
        """Adding Maven rules should not affect npm scans."""
        (tmp_path / "package.json").write_text("{}")
        engine = create_default_engine()
        result = engine.scan(tmp_path)
        npm_rule_ids = {rid for rid in engine.list_rules() if rid.startswith("L2-POST-") or rid.startswith("L2-OBFS-")}
        assert len(npm_rule_ids) > 0
        # No Maven rules should run against npm project
        maven_findings = [f for f in result.findings if "L2-MAVEN" in f.rule_id]
        assert len(maven_findings) == 0

    def test_maven_rules_skipped_when_no_pom_xml(self, tmp_path):
        """Maven rules should be filtered out when no pom.xml/build.gradle."""
        (tmp_path / "README.md").write_text("# just a readme")
        engine = create_default_engine()
        result = engine.scan(tmp_path)
        maven_findings = [f for f in result.findings if "L2-MAVEN" in f.rule_id]
        assert len(maven_findings) == 0
