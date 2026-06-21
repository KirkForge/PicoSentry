"""Tests for the indexed typosquat corpus."""

from __future__ import annotations

import json
from pathlib import Path

from picosentry.scan.rules.corpus_index import (
    CorpusIndex,
    check_typosquat_against_index,
    load_indexed_corpus,
    save_indexed_corpus,
)
from picosentry.scan.rules.typosquat_utils import BUILTIN_TOP_100, check_typosquat


def test_index_contains_loaded_names():
    names = {"react", "react-dom", "express", "lodash"}
    index = CorpusIndex(names)
    assert len(index) == 4
    for name in names:
        assert name in index


def test_near_matches_matches_brute_force():
    """The indexed search must return the same results as the brute-force scan."""
    names = BUILTIN_TOP_100[:50]
    corpus = set(names)
    # Treat every name as priority so the brute-force and indexed paths agree.
    index = CorpusIndex(corpus, priority_names=corpus)

    queries = ["reac", "reactt", "expres", "lodas", "typescipt", "nonexistent-xyz"]
    for query in queries:
        expected = check_typosquat(query, corpus, priority_names=corpus)
        actual = check_typosquat_against_index(query, index)
        assert actual == expected, f"mismatch for {query}: {actual} != {expected}"


def test_scoped_names_are_ignored():
    """Names starting with '@' are skipped like the brute-force check does."""
    index = CorpusIndex(["react", "@scope/pkg"])
    assert index.near_matches("@scope/pkg", max_distance=2.0) == []


def test_exact_name_is_not_a_match():
    """A corpus name that equals the query should not be reported as a typosquat."""
    index = CorpusIndex(["react"])
    assert index.near_matches("react", max_distance=2.0) == []


def test_keyboard_distance_mode():
    """Keyboard-distance mode finds adjacent-key substitutions."""
    index = CorpusIndex(["react"])
    matches = index.near_matches("reavt", max_distance=1.0, use_keyboard=True)
    assert matches == [("react", 0.5)]


def test_load_and_save_indexed_corpus(tmp_path: Path):
    """save_indexed_corpus writes JSON and load_indexed_corpus rebuilds the index."""
    names = ["pkg-a", "pkg-b", "pkg-c"]
    save_indexed_corpus(tmp_path, "npm", names)
    corpus_file = tmp_path / "npm_top_packages.json"
    assert corpus_file.is_file()
    assert set(json.loads(corpus_file.read_text(encoding="utf-8"))) == set(names)

    index = load_indexed_corpus(tmp_path, "npm")
    assert len(index) == 3
    assert "pkg-a" in index


def test_load_indexed_corpus_falls_back_to_builtin(tmp_path: Path):
    """When no corpus file exists, the built-in list is indexed."""
    index = load_indexed_corpus(tmp_path, "npm", BUILTIN_TOP_100)
    assert len(index) == len(BUILTIN_TOP_100)
    assert "react" in index


def test_index_scales_without_crashing():
    """Building and querying a 10k-name index should complete promptly."""
    names = [f"pkg-{i:05d}" for i in range(10_000)]
    index = CorpusIndex(names)
    # The exact result is less important than the call completing quickly.
    matches = index.near_matches("pkg-00000x", max_distance=2.0)
    assert isinstance(matches, list)
