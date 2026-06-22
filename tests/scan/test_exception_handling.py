"""Regression tests for silent exception swallowing in scan rule/detection paths.

These tests verify that malformed input files produce a visible warning and do
not cause the scanner to crash or silently return without explanation.
"""

from __future__ import annotations

import logging
from pathlib import Path


from picosentry.scan.rules.advisory_check import _collect_pypi_packages
from picosentry.scan.rules.dep_confusion import _pypi_has_private_index
from picosentry.scan.rules.pypi_lock_parser import parse_poetry_lock, parse_uv_lock
from picosentry.scan.rules.pypi_utils import extract_metadata, load_pyproject_toml


def test_parse_poetry_lock_bad_toml_logs_warning(tmp_path: Path, caplog):
    lock = tmp_path / "poetry.lock"
    lock.write_text('[[package]\nname = "oops\n', encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="picosentry.pypi_lock_parser"):
        entries = parse_poetry_lock(lock)

    assert entries == []
    assert any("Skipping poetry.lock" in rec.message for rec in caplog.records)


def test_parse_uv_lock_bad_toml_logs_warning(tmp_path: Path, caplog):
    lock = tmp_path / "uv.lock"
    lock.write_text("version = 1\n[[distribution\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="picosentry.pypi_lock_parser"):
        entries = parse_uv_lock(lock)

    assert entries == []
    assert any("Skipping uv.lock" in rec.message for rec in caplog.records)


def test_extract_metadata_bad_email_logs_warning(tmp_path: Path, caplog, monkeypatch):
    metadata = tmp_path / "METADATA"
    metadata.write_text("Name: pkg\nVersion: 1.0.0\n", encoding="utf-8")

    def _bad_parse(_content):
        raise ValueError("simulated email parse error")

    monkeypatch.setattr("email.message_from_string", _bad_parse)

    with caplog.at_level(logging.WARNING, logger="picosentry.pypi_utils"):
        result = extract_metadata(metadata)

    assert result is None
    assert any("Skipping malformed metadata" in rec.message for rec in caplog.records)


def test_load_pyproject_toml_bad_toml_logs_warning(tmp_path: Path, caplog):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.poetry\nname = "pkg"\n', encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="picosentry.pypi_utils"):
        result = load_pyproject_toml(tmp_path)

    assert result is None
    assert any("Skipping pyproject.toml" in rec.message for rec in caplog.records)


def test_pypirc_bad_config_logs_warning(tmp_path: Path, caplog):
    pypirc = tmp_path / ".pypirc"
    pypirc.write_text("[distutils]\nindex-servers =\n[invalid section\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="picosentry.dep_confusion"):
        result = _pypi_has_private_index(tmp_path)

    assert result is False
    assert any("Could not parse .pypirc" in rec.message for rec in caplog.records)


def test_advisory_check_bad_lockfile_logs_warning(tmp_path: Path, caplog, monkeypatch):
    """An unexpected lock-parser failure inside _collect_pypi_packages logs a warning."""
    poetry = tmp_path / "poetry.lock"
    poetry.write_text("not valid toml [[", encoding="utf-8")
    # Also create a valid pyproject.toml so the function doesn't short-circuit.
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "1.0.0"\ndependencies = ["requests"]\n',
        encoding="utf-8",
    )

    def _failing_parser(_path):
        raise ValueError("simulated lock parser failure")

    from picosentry.scan.rules import advisory_check

    monkeypatch.setattr(advisory_check, "parse_poetry_lock", _failing_parser)

    with caplog.at_level(logging.WARNING, logger="picosentry.advisory_check"):
        packages = _collect_pypi_packages(tmp_path)

    # The advisory catch path should log a warning and keep going.
    assert any("Skipping lock file" in rec.message for rec in caplog.records)
    assert any(pkg[0] == "requests" for pkg in packages)


def test_ioc_detection_bad_corpus_logs_critical(tmp_path: Path, caplog, monkeypatch):
    """An unexpected IoC load failure logs a critical message and skips the rule."""
    from picosentry.scan.rules import ioc_detection

    def _failing_loader():
        raise RuntimeError("simulated IoC corpus failure")

    monkeypatch.setattr(ioc_detection, "load_all_iocs", _failing_loader)

    with caplog.at_level(logging.CRITICAL, logger="picosentry.ioc_detection"):
        findings = ioc_detection.detect_custom_iocs(tmp_path)

    assert findings == []
    assert any("Unexpected error loading IoCs" in rec.message for rec in caplog.records)


def test_poetry_lock_valid_entries_still_parsed(tmp_path: Path):
    lock = tmp_path / "poetry.lock"
    lock.write_text(
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
        'category = "main"\noptional = false\npython-versions = ">=3.7"\n',
        encoding="utf-8",
    )

    entries = parse_poetry_lock(lock)
    assert len(entries) == 1
    assert entries[0][0] == "requests"
    assert entries[0][1] == "2.31.0"


def test_uv_lock_valid_entries_still_parsed(tmp_path: Path):
    lock = tmp_path / "uv.lock"
    lock.write_text(
        'version = 1\n[[distribution]]\nname = "httpx"\nversion = "0.24.1"\n'
        'source = { registry = "https://pypi.org/simple" }\n',
        encoding="utf-8",
    )

    entries = parse_uv_lock(lock)
    assert len(entries) == 1
    assert entries[0][0] == "httpx"
    assert entries[0][1] == "0.24.1"
