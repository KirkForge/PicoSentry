from __future__ import annotations

import json
from pathlib import Path

from picosentry.scan.package_intel import PackageIntel
from picosentry.scan.rules.namespace_collision import (
    LOW_DOWNLOAD_THRESHOLD,
    NAMESPACE_PREFIXES,
    SCOPE_PREFIXES,
    YOUNG_AGE_THRESHOLD_DAYS,
    detect_namespace_collision,
)


def _make_project(tmp_path: Path, name: str = "@google/legacy") -> Path:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": name, "version": "1.0.0", "maintainers": [{"name": "anon"}]})
    )
    return tmp_path


def _intel(downloads: int | None, age: int | None) -> PackageIntel:
    return PackageIntel(download_count=downloads, package_age_days=age)


class TestNamespaceCollisionRule:
    def test_flags_colliding_scoped_new_low_download(self, tmp_path):
        target = _make_project(tmp_path, "@google/legacy")
        findings = detect_namespace_collision(
            target, package_intel={"@google/legacy": _intel(5, 3)}
        )
        assert any(f.rule_id == "L2-NSCOL-001" for f in findings)

    def test_flags_unscoped_namespace_collision(self, tmp_path):
        target = _make_project(tmp_path, "google-cloud-storage-clone")
        findings = detect_namespace_collision(
            target, package_intel={"google-cloud-storage-clone": _intel(5, 3)}
        )
        assert any(f.rule_id == "L2-NSCOL-001" for f in findings)

    def test_no_flag_legit_scoped_when_established(self, tmp_path):
        target = _make_project(tmp_path, "@google/real")
        findings = detect_namespace_collision(
            target, package_intel={"@google/real": _intel(5000, 400)}
        )
        assert not any(f.rule_id == "L2-NSCOL-001" for f in findings)

    def test_no_flag_legit_unknown_scope_new_low_download(self, tmp_path):
        target = _make_project(tmp_path, "@acme-corner/utility")
        findings = detect_namespace_collision(
            target, package_intel={"@acme-corner/utility": _intel(5, 3)}
        )
        assert not any(f.rule_id == "L2-NSCOL-001" for f in findings)

    def test_no_flag_wellknown_scope_when_many_downloads(self, tmp_path):
        target = _make_project(tmp_path, "@types/node")
        findings = detect_namespace_collision(
            target, package_intel={"@types/node": _intel(9000, 3)}
        )
        assert not any(f.rule_id == "L2-NSCOL-001" for f in findings)

    def test_no_flag_wellknown_scope_when_old_but_low_downloads(self, tmp_path):
        target = _make_project(tmp_path, "@azure/legacy")
        findings = detect_namespace_collision(
            target, package_intel={"@azure/legacy": _intel(5, 400)}
        )
        assert not any(f.rule_id == "L2-NSCOL-001" for f in findings)

    def test_no_flag_without_intel(self, tmp_path):
        target = _make_project(tmp_path, "@google/legacy")
        findings = detect_namespace_collision(target, package_intel=None)
        assert not any(f.rule_id == "L2-NSCOL-001" for f in findings)

    def test_no_flag_when_intel_missing_fields(self, tmp_path):
        target = _make_project(tmp_path, "@google/legacy")
        findings = detect_namespace_collision(
            target, package_intel={"@google/legacy": PackageIntel()}
        )
        assert not any(f.rule_id == "L2-NSCOL-001" for f in findings)

    def test_no_flag_unscoped_unknown_name(self, tmp_path):
        target = _make_project(tmp_path, "acme-corner-utility")
        findings = detect_namespace_collision(
            target, package_intel={"acme-corner-utility": _intel(5, 3)}
        )
        assert not any(f.rule_id == "L2-NSCOL-001" for f in findings)


class TestNamespaceThresholds:
    def test_thresholds_are_not_lowered(self):
        assert LOW_DOWNLOAD_THRESHOLD == 100
        assert YOUNG_AGE_THRESHOLD_DAYS == 30

    def test_scope_and_namespace_prefixes_present(self):
        assert "@google" in SCOPE_PREFIXES
        assert "google-" in NAMESPACE_PREFIXES
