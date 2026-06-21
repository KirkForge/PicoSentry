"""Tests for the extended multi-ecosystem corpus update command."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from picosentry.scan.cli_commands.update import (
    _BUILTIN_FALLBACK,
    _SUPPORTED_ECOSYSTEMS,
    _fetch_cargo,
    _fetch_go,
    _fetch_maven,
    _fetch_npm,
    _fetch_nuget,
    _fetch_pypi,
    _fetch_rubygems,
    cmd,
)


def _make_urlopen_mock(body: bytes):
    """Return a safe_urlopen-compatible mock returning (response, body)."""
    response = MagicMock()
    return MagicMock(return_value=(response, body))


def test_update_all_ecosystems_writes_manifest(tmp_path: Path):
    """Updating all ecosystems writes per-ecosystem files and a manifest."""

    def mock_urlopen(req, **kwargs):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "npm-rank" in url:
            body = json.dumps(
                [{"name": "express"}, {"name": "lodash"}]
            ).encode("utf-8")
        elif "hugovk.github.io" in url:
            body = json.dumps(
                {"rows": [{"project": "requests"}, {"project": "urllib3"}]}
            ).encode("utf-8")
        elif "crates.io" in url:
            body = json.dumps(
                {"crates": [{"id": "serde"}, {"id": "tokio"}]}
            ).encode("utf-8")
        elif "mvdan/corpus" in url:
            body = b"module\tcount\ngithub.com/gin-gonic/gin\t100\ngithub.com/urfave/cli\t90\n"
        elif "packages.ecosyste.ms" in url and "maven" in url:
            body = json.dumps(
                [{"name": "com.google.guava:guava"}, {"name": "org.slf4j:slf4j-api"}]
            ).encode("utf-8")
        elif "packages.ecosyste.ms" in url and "rubygems" in url:
            body = json.dumps(
                [{"name": "rails"}, {"name": "rake"}]
            ).encode("utf-8")
        elif "nuget.org" in url:
            body = json.dumps(
                {
                    "data": [
                        {"id": "Newtonsoft.Json", "totalDownloads": 1_000_000},
                        {"id": "EntityFramework", "totalDownloads": 900_000},
                    ]
                }
            ).encode("utf-8")
        else:
            raise RuntimeError(f"unexpected URL: {url}")
        response = MagicMock()
        return response, body

    args = argparse.Namespace(
        ecosystem="all",
        top=2,
        output=str(tmp_path),
        source_url=None,
        merge=True,
    )

    with patch("picosentry.scan.cli_commands.update.safe_urlopen", mock_urlopen):
        result = cmd(args)

    assert result == 0

    manifest_path = tmp_path / "corpus.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert "ecosystems" in manifest
    for ecosystem in _SUPPORTED_ECOSYSTEMS:
        assert manifest["ecosystems"][ecosystem]["count"] >= 1
        assert manifest["ecosystems"][ecosystem]["used_builtin"] is False
        corpus_file = tmp_path / f"{ecosystem}_top_packages.json"
        assert corpus_file.is_file()
        data = json.loads(corpus_file.read_text(encoding="utf-8"))
        assert len(data) >= 1


def test_update_npm_fetcher_parses_npm_rank():
    """The npm fetcher extracts names from the npm-rank dataset."""
    body = json.dumps(
        [{"name": "express"}, {"name": "lodash"}, {"name": ""}]
    ).encode("utf-8")
    mock_urlopen = _make_urlopen_mock(body)

    with patch("picosentry.scan.cli_commands.update.safe_urlopen", mock_urlopen):
        names, source_url, used_builtin = _fetch_npm(2)

    assert names == ["express", "lodash"]
    assert not used_builtin
    assert "npm-rank" in source_url


def test_update_pypi_fetcher_parses_leaderboard():
    """The PyPI fetcher extracts project names from the public leaderboard."""
    body = json.dumps(
        {"rows": [{"project": "requests"}, {"project": "numpy"}, {"project": ""}]}
    ).encode("utf-8")
    mock_urlopen = _make_urlopen_mock(body)

    with patch("picosentry.scan.cli_commands.update.safe_urlopen", mock_urlopen):
        names, source_url, used_builtin = _fetch_pypi(2)

    assert names == ["requests", "numpy"]
    assert not used_builtin
    assert "hugovk.github.io" in source_url


def test_update_cargo_fetcher_parses_crates_io():
    """The cargo fetcher extracts crate ids from crates.io."""
    body = json.dumps(
        {"crates": [{"id": "serde"}, {"id": "tokio"}]}
    ).encode("utf-8")
    mock_urlopen = _make_urlopen_mock(body)

    with patch("picosentry.scan.cli_commands.update.safe_urlopen", mock_urlopen):
        names, source_url, used_builtin = _fetch_cargo(2)

    assert names == ["serde", "tokio"]
    assert not used_builtin
    assert "crates.io" in source_url


def test_update_go_fetcher_parses_tsv():
    """The Go fetcher extracts module paths from the mvdan/corpus TSV."""
    body = b"module\tcount\ngithub.com/gin-gonic/gin\t100\ngithub.com/urfave/cli\t90\n"
    mock_urlopen = _make_urlopen_mock(body)

    with patch("picosentry.scan.cli_commands.update.safe_urlopen", mock_urlopen):
        names, source_url, used_builtin = _fetch_go(2)

    assert names == ["github.com/gin-gonic/gin", "github.com/urfave/cli"]
    assert not used_builtin
    assert "mvdan/corpus" in source_url


def test_update_maven_fetcher_parses_ecosyste_ms():
    """The Maven fetcher extracts package names from Ecosyste.ms."""
    body = json.dumps(
        [{"name": "com.google.guava:guava"}, {"name": "org.slf4j:slf4j-api"}]
    ).encode("utf-8")
    mock_urlopen = _make_urlopen_mock(body)

    with patch("picosentry.scan.cli_commands.update.safe_urlopen", mock_urlopen):
        names, source_url, used_builtin = _fetch_maven(2)

    assert names == ["com.google.guava:guava", "org.slf4j:slf4j-api"]
    assert not used_builtin
    assert "ecosyste.ms" in source_url


def test_update_rubygems_fetcher_parses_ecosyste_ms():
    """The RubyGems fetcher extracts package names from Ecosyste.ms."""
    body = json.dumps([{"name": "rails"}, {"name": "rake"}]).encode("utf-8")
    mock_urlopen = _make_urlopen_mock(body)

    with patch("picosentry.scan.cli_commands.update.safe_urlopen", mock_urlopen):
        names, source_url, used_builtin = _fetch_rubygems(2)

    assert names == ["rails", "rake"]
    assert not used_builtin
    assert "ecosyste.ms" in source_url


def test_update_nuget_fetcher_parses_search():
    """The NuGet fetcher extracts ids sorted by total downloads."""
    body = json.dumps(
        {
            "data": [
                {"id": "LessPopular", "totalDownloads": 100},
                {"id": "MostPopular", "totalDownloads": 1_000_000},
            ]
        }
    ).encode("utf-8")
    mock_urlopen = _make_urlopen_mock(body)

    with patch("picosentry.scan.cli_commands.update.safe_urlopen", mock_urlopen):
        names, source_url, used_builtin = _fetch_nuget(2)

    assert names == ["MostPopular", "LessPopular"]
    assert not used_builtin
    assert "nuget.org" in source_url


def test_update_merges_builtin_and_filters_obscure_short_names(tmp_path: Path):
    """Fetched names under 4 chars not in the built-in list are dropped."""
    npm_response = json.dumps(
        [{"name": "express"}, {"name": "x"}]
    ).encode("utf-8")

    args = argparse.Namespace(
        ecosystem="npm",
        top=2,
        output=str(tmp_path / "npm_top_packages.json"),
        source_url=None,
        merge=True,
    )

    def mock_urlopen(req, **kwargs):
        response = MagicMock()
        return response, npm_response

    with patch("picosentry.scan.cli_commands.update.safe_urlopen", mock_urlopen):
        result = cmd(args)

    assert result == 0
    data = json.loads((tmp_path / "npm_top_packages.json").read_text(encoding="utf-8"))
    assert "express" in data
    assert "x" not in data
    for builtin in _BUILTIN_FALLBACK["npm"]:
        assert builtin in data


def test_update_no_merge_still_keeps_builtin_fallback(tmp_path: Path):
    """Even with --no-merge, the built-in fallback list is preserved."""
    npm_response = json.dumps([{"name": "new-pkg"}]).encode("utf-8")

    args = argparse.Namespace(
        ecosystem="npm",
        top=1,
        output=str(tmp_path / "npm_top_packages.json"),
        source_url=None,
        merge=False,
    )

    def mock_urlopen(req, **kwargs):
        response = MagicMock()
        return response, npm_response

    with patch("picosentry.scan.cli_commands.update.safe_urlopen", mock_urlopen):
        result = cmd(args)

    assert result == 0
    data = json.loads((tmp_path / "npm_top_packages.json").read_text(encoding="utf-8"))
    assert "new-pkg" in data
    for builtin in _BUILTIN_FALLBACK["npm"]:
        assert builtin in data


def test_update_merges_with_existing_corpus(tmp_path: Path):
    """When merge is enabled, existing names are preserved."""
    existing = tmp_path / "npm_top_packages.json"
    existing.write_text(json.dumps(["old-pkg"]), encoding="utf-8")

    body = json.dumps([{"name": "new-pkg"}]).encode("utf-8")
    args = argparse.Namespace(
        ecosystem="npm",
        top=10,
        output=str(existing),
        source_url=None,
        merge=True,
    )

    with patch("picosentry.scan.cli_commands.update.safe_urlopen", _make_urlopen_mock(body)):
        result = cmd(args)

    assert result == 0
    data = json.loads(existing.read_text(encoding="utf-8"))
    assert "old-pkg" in data
    assert "new-pkg" in data


def test_builtin_fallback_lists_are_non_empty():
    """Every supported ecosystem has a non-empty built-in fallback."""
    for ecosystem in _SUPPORTED_ECOSYSTEMS:
        assert _BUILTIN_FALLBACK[ecosystem], f"missing builtin fallback for {ecosystem}"
