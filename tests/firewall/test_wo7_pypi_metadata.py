"""WO7-013 — PyPI scan blind to author/maintainer/repo/provenance.

pypi_metadata.json was written but no rule read it. npm fires 6 rules with
the same metadata shape; PyPI fired 0. The fix writes a package.json
mapping PyPI metadata → npm shape so the existing npm rules fire on PyPI.
"""

from __future__ import annotations

from picosentry.firewall.scanner import FirewallScanner, FirewallVerdict, _pypi_to_npm_manifest


class TestPypiToNpmManifest:
    def test_basic_mapping(self):
        info = {"name": "test-pkg", "version": "1.0.0", "author": "Jane", "author_email": "jane@example.com"}
        m = _pypi_to_npm_manifest("test-pkg", "1.0.0", info)
        assert m is not None
        assert m["name"] == "test-pkg"
        assert m["version"] == "1.0.0"
        assert m["author"]["name"] == "Jane"
        assert m["author"]["email"] == "jane@example.com"

    def test_maintainer_mapping(self):
        info = {"name": "pkg", "version": "1.0", "maintainer": "Bob", "maintainer_email": "bob@example.com"}
        m = _pypi_to_npm_manifest("pkg", "1.0", info)
        assert m["maintainers"][0]["name"] == "Bob"
        assert m["maintainers"][0]["email"] == "bob@example.com"

    def test_repository_mapping_from_home_page(self):
        info = {"name": "pkg", "version": "1.0", "home_page": "https://github.com/org/pkg"}
        m = _pypi_to_npm_manifest("pkg", "1.0", info)
        assert m["repository"]["url"] == "https://github.com/org/pkg"

    def test_repository_mapping_from_project_urls(self):
        info = {"name": "pkg", "version": "1.0", "project_urls": {"Repository": "https://github.com/org/pkg"}}
        m = _pypi_to_npm_manifest("pkg", "1.0", info)
        assert m["repository"]["url"] == "https://github.com/org/pkg"

    def test_description_mapping(self):
        info = {"name": "pkg", "version": "1.0", "summary": "A test package"}
        m = _pypi_to_npm_manifest("pkg", "1.0", info)
        assert m["description"] == "A test package"

    def test_license_mapping(self):
        info = {"name": "pkg", "version": "1.0", "license": "MIT"}
        m = _pypi_to_npm_manifest("pkg", "1.0", info)
        assert m["license"] == "MIT"

    def test_requires_dist_mapping(self):
        info = {"name": "pkg", "version": "1.0", "requires_dist": ["requests>=2.20", "flask"]}
        m = _pypi_to_npm_manifest("pkg", "1.0", info)
        assert "requests" in m["dependencies"]
        assert "flask" in m["dependencies"]


class TestPypiMetadataRulesFire:
    def test_suspicious_author_fires_rule(self):
        scanner = FirewallScanner()
        info = {
            "name": "acme-pypi-suspicious",
            "version": "1.0.0",
            "author": "x",
            "author_email": "x@temp.com",
            "home_page": "https://github.com/acme/acme-pypi-suspicious",
        }
        _verdict, findings = scanner.scan_metadata("pypi", "acme-pypi-suspicious", "1.0.0", {"info": info})
        assert any(f.rule_id.startswith("L2-") for f in findings), (
            "PyPI metadata must fire at least one rule (was 0 before the fix)"
        )

    def test_no_repository_fires_provenance(self):
        scanner = FirewallScanner()
        info = {
            "name": "acme-pypi-norepo",
            "version": "1.0.0",
            "author": "Someone",
            "author_email": "someone@example.com",
        }
        _verdict, findings = scanner.scan_metadata("pypi", "acme-pypi-norepo", "1.0.0", {"info": info})
        assert any(f.rule_id == "L2-PROV-001" for f in findings), (
            "PyPI package with no repository should fire L2-PROV-001"
        )

    def test_clean_pypi_package_no_false_block(self):
        scanner = FirewallScanner()
        info = {
            "name": "acme-pypi-clean",
            "version": "1.0.0",
            "author": "Acme Corp",
            "author_email": "dev@acme.example",
            "home_page": "https://github.com/acme/clean-pkg",
            "license": "MIT",
            "summary": "A clean package",
        }
        verdict, _findings = scanner.scan_metadata("pypi", "acme-pypi-clean", "1.0.0", {"info": info})
        assert verdict != FirewallVerdict.BLOCK, "clean PyPI package must not BLOCK"
