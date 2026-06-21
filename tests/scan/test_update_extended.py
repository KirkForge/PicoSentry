"""Tests for the extended multi-ecosystem corpus update command."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from picosentry.scan.cli_commands.update import _BUILTIN_FALLBACK, _fetch_pypi, _fetch_npm, cmd


def _mock_urlopen(response_data: bytes):
    """Create a mock urllib.request.urlopen returning response_data."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = response_data
    return MagicMock(return_value=mock_resp)


def test_update_all_ecosystems_writes_manifest(tmp_path: Path):
    """Updating all ecosystems writes per-ecosystem files and a manifest."""
    npm_response = json.dumps(
        {"objects": [{"package": {"name": "express"}}], "total": 1}
    ).encode("utf-8")
    pypi_response = json.dumps(
        {"rows": [{"project": "requests"}, {"project": "urllib3"}]}
    ).encode("utf-8")

    args = argparse.Namespace(
        ecosystem="all",
        top=2,
        output=str(tmp_path),
        source_url=None,
        merge=True,
    )

    def mock_urlopen(req, **kwargs):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "npmjs.org" in url:
            return _mock_urlopen(npm_response)()
        if "hugovk.github.io" in url:
            return _mock_urlopen(pypi_response)()
        raise RuntimeError(f"unexpected URL: {url}")

    with patch("urllib.request.urlopen", mock_urlopen):
        result = cmd(args)

    assert result == 0

    manifest_path = tmp_path / "corpus.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert "ecosystems" in manifest
    assert manifest["ecosystems"]["npm"]["count"] >= 1
    assert manifest["ecosystems"]["pypi"]["count"] >= 2

    # Ecosystems without a live fetcher should fall back to the built-in list.
    for ecosystem in ("go", "cargo", "maven", "rubygems", "nuget"):
        assert manifest["ecosystems"][ecosystem]["used_builtin"] is True
        corpus_file = tmp_path / f"{ecosystem}_top_packages.json"
        assert corpus_file.is_file()
        data = json.loads(corpus_file.read_text(encoding="utf-8"))
        assert len(data) > 0


def test_update_pypi_fetcher_parses_leaderboard():
    """The PyPI fetcher extracts project names from the public leaderboard."""
    body = json.dumps(
        {"rows": [{"project": "requests"}, {"project": "numpy"}, {"project": ""}]}
    ).encode("utf-8")
    mock_urlopen = _mock_urlopen(body)

    with patch("urllib.request.urlopen", mock_urlopen):
        names, source_url, used_builtin = _fetch_pypi(2)

    assert names == ["requests", "numpy"]
    assert not used_builtin
    assert "hugovk.github.io" in source_url


def test_update_npm_fetcher_parses_search():
    """The npm fetcher extracts package names from the registry search response."""
    body = json.dumps(
        {"objects": [{"package": {"name": "express"}}, {"package": {"name": "@scope/pkg"}}], "total": 1}
    ).encode("utf-8")
    mock_urlopen = _mock_urlopen(body)

    with patch("urllib.request.urlopen", mock_urlopen):
        names, source_url, used_builtin = _fetch_npm(10)

    assert names == ["express"]
    assert not used_builtin
    assert "npmjs.org" in source_url


def test_update_merges_with_existing_corpus(tmp_path: Path):
    """When merge is enabled, existing names are preserved."""
    existing = tmp_path / "npm_top_packages.json"
    existing.write_text(json.dumps(["old-pkg"]), encoding="utf-8")

    body = json.dumps({"objects": [{"package": {"name": "new-pkg"}}], "total": 1}).encode("utf-8")
    args = argparse.Namespace(
        ecosystem="npm",
        top=10,
        output=str(existing),
        source_url=None,
        merge=True,
    )

    with patch("urllib.request.urlopen", _mock_urlopen(body)):
        result = cmd(args)

    assert result == 0
    data = json.loads(existing.read_text(encoding="utf-8"))
    assert "old-pkg" in data
    assert "new-pkg" in data


def test_update_no_merge_overwrites_existing_corpus(tmp_path: Path):
    """When merge is disabled, existing names are discarded."""
    existing = tmp_path / "npm_top_packages.json"
    existing.write_text(json.dumps(["old-pkg"]), encoding="utf-8")

    body = json.dumps({"objects": [{"package": {"name": "new-pkg"}}], "total": 1}).encode("utf-8")
    args = argparse.Namespace(
        ecosystem="npm",
        top=10,
        output=str(existing),
        source_url=None,
        merge=False,
    )

    with patch("urllib.request.urlopen", _mock_urlopen(body)):
        result = cmd(args)

    assert result == 0
    data = json.loads(existing.read_text(encoding="utf-8"))
    assert "old-pkg" not in data
    assert "new-pkg" in data


def test_builtin_fallback_lists_are_non_empty():
    """Every supported ecosystem has a non-empty built-in fallback."""
    from picosentry.scan.cli_commands.update import _SUPPORTED_ECOSYSTEMS

    for ecosystem in _SUPPORTED_ECOSYSTEMS:
        assert _BUILTIN_FALLBACK[ecosystem], f"missing builtin fallback for {ecosystem}"
