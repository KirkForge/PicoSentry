"""Tests for reachability analysis on advisory findings (WO2.0.0-011)."""

from __future__ import annotations

import json
from pathlib import Path

from picosentry.scan.rules.advisory_check import detect_all_advisory_vulnerabilities


def _write_osv_advisory(directory: Path, pkg_name: str, adv_id: str = "GHSA-reach-0001") -> None:
    """Write a minimal OSV advisory for ``pkg_name`` into ``directory``."""
    data = {
        "id": adv_id,
        "summary": "Test reachability advisory",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": pkg_name},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}],
            }
        ],
        "database_specific": {"severity": "HIGH"},
        "published": "2024-01-01",
    }
    (directory / f"{adv_id}.json").write_text(json.dumps(data), encoding="utf-8")


def _make_project(tmp_path: Path, requirements: str, source_files: dict[str, str]) -> Path:
    """Build a pypi project tree with a requirements.txt and optional source files."""
    (tmp_path / "requirements.txt").write_text(requirements, encoding="utf-8")
    for rel, content in source_files.items():
        fpath = tmp_path / rel
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content, encoding="utf-8")
    return tmp_path


def _run_scan(project: Path, advisory_dir: Path) -> list:
    corpus_dir = project / "corpus"
    corpus_dir.mkdir(exist_ok=True)
    (corpus_dir / "advisories").mkdir(exist_ok=True)
    return detect_all_advisory_vulnerabilities(project, corpus_dir, advisory_db_path=str(advisory_dir))


def test_vulnerable_dep_imported_is_reachable(tmp_path: Path) -> None:
    """A vulnerable dep that is imported in source is flagged reachable=True."""
    advisory_dir = tmp_path / "advisories"
    advisory_dir.mkdir()
    _write_osv_advisory(advisory_dir, "requests")

    project = _make_project(
        tmp_path,
        "requests==1.0.0\n",
        {"app.py": "import requests\nresp = requests.get('https://example.com')\n"},
    )

    findings = _run_scan(project, advisory_dir)
    assert findings, "Expected an advisory finding for the vulnerable dep"
    assert all(f.reachable for f in findings), "Imported vulnerable dep should be reachable=True"


def test_vulnerable_dep_present_but_unused_is_not_reachable(tmp_path: Path) -> None:
    """A vulnerable dep present in the lockfile but never imported is reachable=False."""
    advisory_dir = tmp_path / "advisories"
    advisory_dir.mkdir()
    _write_osv_advisory(advisory_dir, "requests")

    project = _make_project(
        tmp_path,
        "requests==1.0.0\n",
        {"app.py": "import os\nprint(os.getcwd())\n"},
    )

    findings = _run_scan(project, advisory_dir)
    assert findings, "Expected an advisory finding for the vulnerable dep"
    assert all(not f.reachable for f in findings), "Unused vulnerable dep should be reachable=False"


def test_reachable_flag_serialized_in_finding_dict(tmp_path: Path) -> None:
    """The reachable flag is emitted in Finding.to_dict()."""
    advisory_dir = tmp_path / "advisories"
    advisory_dir.mkdir()
    _write_osv_advisory(advisory_dir, "requests")

    project = _make_project(
        tmp_path,
        "requests==1.0.0\n",
        {"app.py": "import requests\n"},
    )

    findings = _run_scan(project, advisory_dir)
    assert findings
    d = findings[0].to_dict()
    assert "reachable" in d
    assert d["reachable"] is True
