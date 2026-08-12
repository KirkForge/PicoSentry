from __future__ import annotations

import json
from pathlib import Path

from picosentry.scan._network import fetch_registry_intel
from picosentry.scan.package_intel import PackageIntel, _age_days_from_iso, enrich_registry_intel
from picosentry.scan.rules.package_age import (
    LOW_DOWNLOAD_THRESHOLD,
    YOUNG_AGE_THRESHOLD_DAYS,
    detect_suspicious_new_packages,
)


def _make_project(tmp_path: Path, name: str = "suspicious-new-pkg") -> Path:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": name, "version": "1.0.0", "maintainers": [{"name": "anon"}]})
    )
    return tmp_path


class TestAgeHelper:
    def test_iso_parse(self):
        assert _age_days_from_iso("2026-08-01T00:00:00Z") is not None

    def test_none_returns_none(self):
        assert _age_days_from_iso(None) is None

    def test_invalid_returns_none(self):
        assert _age_days_from_iso("not-a-date") is None


class TestEnrichRegistryIntel:
    def test_offline_noop(self):
        intel = PackageIntel()
        out = enrich_registry_intel(intel, None, None)
        assert out.download_count is None
        assert out.package_age_days is None

    def test_populates_fields(self):
        intel = PackageIntel()
        out = enrich_registry_intel(intel, 5, "2026-08-01T00:00:00Z")
        assert out.download_count == 5
        assert out.package_age_days is not None

    def test_returns_new_instance(self):
        intel = PackageIntel()
        out = enrich_registry_intel(intel, 1, "2026-08-01T00:00:00Z")
        assert out is not intel


class TestSuspiciousNewPackageRule:
    def test_flags_young_low_download(self, tmp_path):
        target = _make_project(tmp_path)
        intel = PackageIntel(download_count=5, package_age_days=3)
        findings = detect_suspicious_new_packages(target, package_intel={"suspicious-new-pkg": intel})
        assert any(f.rule_id == "L2-INTEL-001" for f in findings)

    def test_no_flag_when_established(self, tmp_path):
        target = _make_project(tmp_path)
        intel = PackageIntel(download_count=5000, package_age_days=400)
        findings = detect_suspicious_new_packages(target, package_intel={"suspicious-new-pkg": intel})
        assert not any(f.rule_id == "L2-INTEL-001" for f in findings)

    def test_no_flag_when_old_but_low_downloads(self, tmp_path):
        target = _make_project(tmp_path)
        intel = PackageIntel(download_count=5, package_age_days=400)
        findings = detect_suspicious_new_packages(target, package_intel={"suspicious-new-pkg": intel})
        assert not any(f.rule_id == "L2-INTEL-001" for f in findings)

    def test_no_flag_when_young_but_many_downloads(self, tmp_path):
        target = _make_project(tmp_path)
        intel = PackageIntel(download_count=5000, package_age_days=3)
        findings = detect_suspicious_new_packages(target, package_intel={"suspicious-new-pkg": intel})
        assert not any(f.rule_id == "L2-INTEL-001" for f in findings)

    def test_no_flag_without_intel(self, tmp_path):
        target = _make_project(tmp_path)
        findings = detect_suspicious_new_packages(target, package_intel=None)
        assert not any(f.rule_id == "L2-INTEL-001" for f in findings)

    def test_no_flag_when_intel_missing_fields(self, tmp_path):
        target = _make_project(tmp_path)
        intel = PackageIntel()  # download_count/package_age_days are None (offline)
        findings = detect_suspicious_new_packages(target, package_intel={"suspicious-new-pkg": intel})
        assert not any(f.rule_id == "L2-INTEL-001" for f in findings)

    def test_thresholds_are_not_lowered(self):
        assert LOW_DOWNLOAD_THRESHOLD == 100
        assert YOUNG_AGE_THRESHOLD_DAYS == 30


class TestRegistryFetchDegradesGracefully:
    def test_offline_returns_none_none(self, monkeypatch):
        def _boom(*args, **kwargs):
            raise OSError("no network")

        monkeypatch.setattr("picosentry.scan._network.safe_urlopen", _boom)
        assert fetch_registry_intel("some-pkg", "npm") == (None, None)
        assert fetch_registry_intel("some-pkg", "pypi") == (None, None)

    def test_pypi_parses_first_release(self, monkeypatch):
        payload = json.dumps(
            {
                "releases": {
                    "1.0.0": [{"upload_time": "2026-08-01T00:00:00Z"}],
                    "1.0.1": [{"upload_time": "2026-08-10T00:00:00Z"}],
                }
            }
        ).encode()

        class _Resp:
            def read(self, n):
                return payload

        monkeypatch.setattr("picosentry.scan._network.safe_urlopen", lambda *a, **k: (_Resp(), payload))
        dl, first = fetch_registry_intel("some-pkg", "pypi")
        assert dl is None
        assert first == "2026-08-01T00:00:00Z"

    def test_npm_parses_downloads_and_created(self, monkeypatch):
        meta = json.dumps({"time": {"created": "2026-08-01T00:00:00Z"}}).encode()
        dl = json.dumps({"downloads": 42}).encode()

        def _fake(url, **kwargs):
            if "downloads" in url:
                return None, dl
            return None, meta

        monkeypatch.setattr("picosentry.scan._network.safe_urlopen", _fake)
        count, first = fetch_registry_intel("some-pkg", "npm")
        assert count == 42
        assert first == "2026-08-01T00:00:00Z"
