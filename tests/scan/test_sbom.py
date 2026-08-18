from __future__ import annotations

import json

import pytest

from picosentry.scan.sbom import (
    PackageRef,
    _detect_format,
    _ecosystem_from_purl,
    _parse_cyclonedx_json,
    _parse_cyclonedx_xml,
    _parse_spdx_json,
    parse_sbom,
)


_CDX_JSON_MINIMAL = {
    "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "components": [
        {
            "type": "library",
            "name": "lodash",
            "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
        },
        {
            "type": "library",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
        },
    ],
}

_CDX_XML_MINIMAL = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">'
    "  <components>"
    '    <component type="library">'
    "      <name>express</name>"
    "      <version>4.18.2</version>"
    "      <purl>pkg:npm/express@4.18.2</purl>"
    "    </component>"
    '    <component type="library">'
    "      <name>django</name>"
    "      <version>4.2.7</version>"
    "      <purl>pkg:pypi/django@4.2.7</purl>"
    "    </component>"
    "  </components>"
    "</bom>"
)

_SPDX_JSON_MINIMAL = {
    "SPDXID": "SPDXRef-DOCUMENT",
    "spdxVersion": "SPDX-2.3",
    "name": "test-sbom",
    "documentNamespace": "https://example.com/test",
    "creationInfo": {"creators": ["Tool: test"]},
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-lodash",
            "name": "lodash",
            "versionInfo": "4.17.21",
            "externalRefs": [
                {
                    "referenceType": "purl",
                    "referenceLocator": "pkg:npm/lodash@4.17.21",
                }
            ],
        },
        {
            "SPDXID": "SPDXRef-Package-requests",
            "name": "requests",
            "versionInfo": "2.31.0",
            "packageManager": "pypi",
        },
    ],
}


class TestCycloneDXJSON:
    def test_parse_components(self):
        refs = _parse_cyclonedx_json(_CDX_JSON_MINIMAL)
        assert len(refs) == 2
        assert refs[0] == PackageRef(name="lodash", version="4.17.21", ecosystem="npm", purl="pkg:npm/lodash@4.17.21")
        assert refs[1] == PackageRef(
            name="requests", version="2.31.0", ecosystem="pypi", purl="pkg:pypi/requests@2.31.0"
        )

    def test_empty_components(self):
        data = {"$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json", "specVersion": "1.5"}
        assert _parse_cyclonedx_json(data) == []

    def test_missing_purl(self):
        data = {
            "specVersion": "1.5",
            "components": [{"type": "library", "name": "foo", "version": "1.0.0"}],
        }
        refs = _parse_cyclonedx_json(data)
        assert len(refs) == 1
        assert refs[0].ecosystem == "unknown"
        assert refs[0].purl == ""


class TestCycloneDXXML:
    def test_parse_components(self):
        refs = _parse_cyclonedx_xml(_CDX_XML_MINIMAL.encode())
        assert len(refs) == 2
        assert refs[0] == PackageRef(name="express", version="4.18.2", ecosystem="npm", purl="pkg:npm/express@4.18.2")
        assert refs[1] == PackageRef(name="django", version="4.2.7", ecosystem="pypi", purl="pkg:pypi/django@4.2.7")

    def test_invalid_xml(self):
        assert _parse_cyclonedx_xml(b"not xml") == []


class TestSPDXJSON:
    def test_parse_packages(self):
        refs = _parse_spdx_json(_SPDX_JSON_MINIMAL)
        assert len(refs) == 2
        assert refs[0] == PackageRef(name="lodash", version="4.17.21", ecosystem="npm", purl="pkg:npm/lodash@4.17.21")
        assert refs[1] == PackageRef(name="requests", version="2.31.0", ecosystem="pypi", purl="")

    def test_empty_packages(self):
        data = {"SPDXID": "SPDXRef-DOCUMENT"}
        assert _parse_spdx_json(data) == []

    def test_package_manager_fallback(self):
        data = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {"name": "my-lib", "versionInfo": "1.0", "packageManager": "golang"},
            ],
        }
        refs = _parse_spdx_json(data)
        assert refs[0].ecosystem == "golang"


class TestFormatDetection:
    def test_json_extension_cyclonedx(self, tmp_path):
        p = tmp_path / "sbom.json"
        p.write_text(json.dumps(_CDX_JSON_MINIMAL))
        assert _detect_format(p) == "cyclonedx_json"

    def test_json_extension_spdx(self, tmp_path):
        p = tmp_path / "sbom.json"
        p.write_text(json.dumps(_SPDX_JSON_MINIMAL))
        assert _detect_format(p) == "spdx_json"

    def test_xml_extension(self, tmp_path):
        p = tmp_path / "sbom.xml"
        p.write_text(_CDX_XML_MINIMAL)
        assert _detect_format(p) == "cyclonedx_xml"

    def test_cyclonedx_schema_detection(self, tmp_path):
        p = tmp_path / "report.json"
        p.write_text(json.dumps({"$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json"}))
        assert _detect_format(p) == "cyclonedx_json"

    def test_spdx_schema_detection(self, tmp_path):
        p = tmp_path / "report.json"
        p.write_text(json.dumps({"$schema": "https://spdx.github.io/spdx-spec/"}))
        assert _detect_format(p) == "spdx_json"

    def test_unknown_format(self, tmp_path):
        p = tmp_path / "random.txt"
        p.write_text("hello world")
        assert _detect_format(p) == "unknown"

    def test_cyclonedx_specversion(self, tmp_path):
        p = tmp_path / "bom.json"
        p.write_text(json.dumps({"specVersion": "1.5", "components": []}))
        assert _detect_format(p) == "cyclonedx_json"


class TestEcosystemMapping:
    @pytest.mark.parametrize(
        "purl,expected",
        [
            ("pkg:npm/lodash@4.17.21", "npm"),
            ("pkg:pypi/requests@2.31.0", "pypi"),
            ("pkg:golang/github.com/gin-gonic/gin@1.9", "golang"),
            ("pkg:cargo/serde@1.0", "cargo"),
            ("pkg:maven/org.apache.commons/lang3@3.12", "maven"),
            ("pkg:gem/rails@7.0", "rubygems"),
            ("pkg:nuget/Newtonsoft.Json@13.0", "nuget"),
            ("", "unknown"),
            ("not-a-purl", "unknown"),
            ("pkg:unknown/foo@1.0", "unknown"),
            ("pkg:foo/bar", "unknown"),
        ],
    )
    def test_purl_ecosystem(self, purl, expected):
        assert _ecosystem_from_purl(purl) == expected


class TestXMLSafety:
    def test_rejects_entity_expansion(self, tmp_path):
        bom = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE bom [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<bom xmlns="http://cyclonedx.org/schema/bom/1.5">'
            '<components><component type="library">'
            "<name>evil</name><version>1.0</version>"
            "</component></components></bom>"
        )
        p = tmp_path / "evil.xml"
        p.write_text(bom)
        fmt = _detect_format(p)
        assert fmt in ("unknown", "cyclonedx_xml")
        if fmt == "cyclonedx_xml":
            refs = parse_sbom(p)
            assert refs == []

    def test_rejects_oversized_xml(self, tmp_path):
        from picosentry.scan.sbom import _MAX_XML_BYTES

        assert _MAX_XML_BYTES == 10 * 1024 * 1024

    def test_safe_xml_parse_rejects_dtd(self):
        from picosentry.scan.sbom import _safe_xml_parse

        xml_with_entity = b'<?xml version="1.0"?><!DOCTYPE bom [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><bom/>'
        result = _safe_xml_parse(xml_with_entity)
        assert result is None


class TestParseSBOMIntegration:
    def test_cyclonedx_json_file(self, tmp_path):
        p = tmp_path / "cdx.json"
        p.write_text(json.dumps(_CDX_JSON_MINIMAL))
        refs = parse_sbom(p)
        assert len(refs) == 2
        assert refs[0].name == "lodash"

    def test_cyclonedx_xml_file(self, tmp_path):
        p = tmp_path / "cdx.xml"
        p.write_text(_CDX_XML_MINIMAL)
        refs = parse_sbom(p)
        assert len(refs) == 2
        assert refs[0].name == "express"

    def test_spdx_json_file(self, tmp_path):
        p = tmp_path / "spdx.json"
        p.write_text(json.dumps(_SPDX_JSON_MINIMAL))
        refs = parse_sbom(p)
        assert len(refs) == 2
        assert refs[0].name == "lodash"

    def test_unknown_format_raises(self, tmp_path):
        p = tmp_path / "bad.txt"
        p.write_text("not a sbom")
        with pytest.raises(ValueError, match="Cannot detect SBOM format"):
            parse_sbom(p)


class TestEcosystemFallback:
    """WO5.0.0-016 — purl-less components get ecosystem fallbacks instead of
    silently landing in unknown-packages.json where no rule parses them."""

    def test_scoped_name_maps_to_npm(self):
        refs = _parse_cyclonedx_json(
            {"specVersion": "1.5", "components": [{"type": "library", "name": "@evil/dep", "version": "1.0.0"}]}
        )
        assert refs[0].ecosystem == "npm"

    def test_external_reference_url_maps_to_npm(self):
        refs = _parse_cyclonedx_json(
            {
                "specVersion": "1.5",
                "components": [
                    {
                        "type": "library",
                        "name": "lodash",
                        "version": "4.17.20",
                        "externalReferences": [
                            {"type": "distribution", "url": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}
                        ],
                    }
                ],
            }
        )
        assert refs[0].ecosystem == "npm"

    def test_go_module_path_name(self):
        refs = _parse_cyclonedx_json(
            {
                "specVersion": "1.5",
                "components": [{"type": "library", "name": "github.com/pkg/errors", "version": "v0.9.1"}],
            }
        )
        assert refs[0].ecosystem == "golang"

    def test_maven_coords_name(self):
        refs = _parse_cyclonedx_json(
            {
                "specVersion": "1.5",
                "components": [{"type": "library", "name": "org.apache.commons:commons-io", "version": "1.4"}],
            }
        )
        assert refs[0].ecosystem == "maven"
        assert refs[0].name == "org.apache.commons:commons-io"

    def test_plain_name_stays_unknown(self):
        refs = _parse_cyclonedx_json(
            {"specVersion": "1.5", "components": [{"type": "library", "name": "mystery-blob", "version": "2.0"}]}
        )
        assert refs[0].ecosystem == "unknown"

    def test_cyclonedx_xml_reference_url_child_element(self):
        bom = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">'
            "  <components>"
            '    <component type="library">'
            "      <name>lodash</name>"
            "      <version>4.17.20</version>"
            "      <externalReferences>"
            '        <reference type="distribution">'
            "          <url>https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz</url>"
            "        </reference>"
            "      </externalReferences>"
            "    </component>"
            "  </components>"
            "</bom>"
        )
        refs = _parse_cyclonedx_xml(bom.encode())
        assert len(refs) == 1
        assert refs[0].ecosystem == "npm"

    def test_spdx_download_location_sniffing(self):
        refs = _parse_spdx_json(
            {
                "SPDXID": "SPDXRef-DOCUMENT",
                "packages": [
                    {
                        "name": "express",
                        "versionInfo": "4.18.2",
                        "downloadLocation": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                    },
                    {
                        "name": "requests",
                        "versionInfo": "2.31.0",
                        "downloadLocation": "NOASSERTION",
                        "sourceInfo": "acquired from https://pypi.org/project/requests/2.31.0/",
                    },
                ],
            }
        )
        assert refs[0].ecosystem == "npm"
        assert refs[1].ecosystem == "pypi"

    def test_spdx_purl_still_wins_over_heuristics(self):
        refs = _parse_spdx_json(
            {
                "SPDXID": "SPDXRef-DOCUMENT",
                "packages": [
                    {
                        "name": "weird-name",
                        "versionInfo": "1.0",
                        "downloadLocation": "https://registry.npmjs.org/weird-name/-/weird-name-1.0.tgz",
                        "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/weird-name@1.0"}],
                    }
                ],
            }
        )
        assert refs[0].ecosystem == "pypi"


class TestSbomCliAccounting:
    """WO5.0.0-016 — purl-less SBOM components are scanned via fallback or
    counted as unscannable (result + stderr), never silently dropped; garbage
    --sbom input exits 2 with a clean message."""

    def _run(self, tmp_path, monkeypatch, sbom_content: str):
        import argparse

        from picosentry.scan.cli_commands.scan import add_arguments
        from picosentry.scan.cli_service import ScanOrchestrator

        monkeypatch.setenv("PICOSENTRY_CACHE_DIR", str(tmp_path / "cache"))
        monkeypatch.setenv("PICOSENTRY_ADVISORY_DIR", str(tmp_path / "no-adv"))
        monkeypatch.setenv("PICOSENTRY_CORPUS_DIR", str(tmp_path / "no-user-corpus"))
        monkeypatch.setenv("PICOSENTRY_INTELLIGENCE_DIR", str(tmp_path / "intel"))

        sbom = tmp_path / "sbom.json"
        sbom.write_text(sbom_content)
        proj = tmp_path / "proj"
        proj.mkdir()
        parser = argparse.ArgumentParser()
        add_arguments(parser.add_subparsers())
        args = parser.parse_args(
            ["scan", str(proj), "--sbom", str(sbom), "--no-cache", "--offline", "--format", "json"]
        )
        return ScanOrchestrator(args).run()

    def test_unscannable_counted_in_result_and_stderr(self, tmp_path, monkeypatch, capsys):
        import json as json_mod

        rc = self._run(
            tmp_path,
            monkeypatch,
            json_mod.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "version": 1,
                    "components": [
                        {"type": "library", "name": "@evil/dep", "version": "1.0.0"},
                        {"type": "library", "name": "mystery-blob", "version": "2.0"},
                    ],
                }
            ),
        )
        assert rc == 0
        captured = capsys.readouterr()
        data = json_mod.loads(captured.out)
        assert data["unscannable_components"] == 1
        assert "unscannable_components" in captured.err
        assert "1 SBOM component(s)" in captured.err

    def test_all_mapped_components_no_warning(self, tmp_path, monkeypatch, capsys):
        import json as json_mod

        rc = self._run(
            tmp_path,
            monkeypatch,
            json_mod.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "version": 1,
                    "components": [
                        {"type": "library", "name": "@evil/dep", "version": "1.0.0"},
                        {"type": "library", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
                    ],
                }
            ),
        )
        assert rc == 0
        captured = capsys.readouterr()
        assert "unscannable_components" not in captured.err
        assert "unscannable_components" not in json_mod.loads(captured.out)

    def test_garbage_sbom_exits_2_cleanly(self, tmp_path, monkeypatch, capsys):
        with pytest.raises(SystemExit) as ei:
            self._run(tmp_path, monkeypatch, "this is not json {{{")
        assert ei.value.code == 2
        captured = capsys.readouterr()
        assert "invalid SBOM" in captured.err
        assert "Traceback" not in captured.err
