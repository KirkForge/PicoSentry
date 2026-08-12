from __future__ import annotations

import json
from pathlib import Path

from picosentry.scan.package_intel import PackageIntel
from picosentry.scan.rules.version_confusion import (
    ESTABLISHED_AGE_THRESHOLD_DAYS,
    POPULAR_DOWNLOAD_THRESHOLD,
    SQUAT_VERSIONS,
    detect_version_confusion,
)


def _make_project(tmp_path: Path, name: str = "squat-pkg", version: str = "1.0.0") -> Path:
    (tmp_path / "package.json").write_text(json.dumps({"name": name, "version": version}))
    return tmp_path


class TestVersionConfusionRule:
    def test_flags_popular_established_at_1_0_0(self, tmp_path):
        target = _make_project(tmp_path, version="1.0.0")
        intel = PackageIntel(download_count=5000, package_age_days=400)
        findings = detect_version_confusion(target, package_intel={"squat-pkg": intel})
        assert any(f.rule_id == "L2-VCONF-001" for f in findings)

    def test_flags_popular_established_at_0_0_0(self, tmp_path):
        target = _make_project(tmp_path, version="0.0.0")
        intel = PackageIntel(download_count=5000, package_age_days=400)
        findings = detect_version_confusion(target, package_intel={"squat-pkg": intel})
        assert any(f.rule_id == "L2-VCONF-001" for f in findings)

    def test_no_flag_legitimate_version(self, tmp_path):
        target = _make_project(tmp_path, version="2.4.1")
        intel = PackageIntel(download_count=5000, package_age_days=400)
        findings = detect_version_confusion(target, package_intel={"squat-pkg": intel})
        assert not any(f.rule_id == "L2-VCONF-001" for f in findings)

    def test_no_flag_young_package_at_1_0_0(self, tmp_path):
        target = _make_project(tmp_path, version="1.0.0")
        intel = PackageIntel(download_count=5000, package_age_days=3)
        findings = detect_version_confusion(target, package_intel={"squat-pkg": intel})
        assert not any(f.rule_id == "L2-VCONF-001" for f in findings)

    def test_no_flag_low_download_at_1_0_0(self, tmp_path):
        target = _make_project(tmp_path, version="1.0.0")
        intel = PackageIntel(download_count=5, package_age_days=400)
        findings = detect_version_confusion(target, package_intel={"squat-pkg": intel})
        assert not any(f.rule_id == "L2-VCONF-001" for f in findings)

    def test_no_flag_without_intel(self, tmp_path):
        target = _make_project(tmp_path, version="1.0.0")
        findings = detect_version_confusion(target, package_intel=None)
        assert not any(f.rule_id == "L2-VCONF-001" for f in findings)

    def test_no_flag_when_intel_missing_fields(self, tmp_path):
        target = _make_project(tmp_path, version="1.0.0")
        intel = PackageIntel()  # download_count/package_age_days are None (offline)
        findings = detect_version_confusion(target, package_intel={"squat-pkg": intel})
        assert not any(f.rule_id == "L2-VCONF-001" for f in findings)

    def test_thresholds_are_not_lowered(self):
        assert POPULAR_DOWNLOAD_THRESHOLD == 1000
        assert ESTABLISHED_AGE_THRESHOLD_DAYS == 30
        assert frozenset({"0.0.0", "1.0.0"}) == SQUAT_VERSIONS
