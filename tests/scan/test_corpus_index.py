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
from picosentry.scan.rules._typosquat_corpus import BUILTIN_TOP_100
from picosentry.scan.rules.typosquat_utils import check_typosquat


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


def test_load_indexed_corpus_caches_repeated_loads(tmp_path: Path):
    """Repeated loads for the same corpus return the cached index."""
    names = ["cached-a", "cached-b"]
    save_indexed_corpus(tmp_path, "npm", names)

    index1 = load_indexed_corpus(tmp_path, "npm")
    index2 = load_indexed_corpus(tmp_path, "npm")
    assert index1 is index2


def test_load_indexed_corpus_invalidates_cache_when_file_changes(tmp_path: Path):
    """Updating the corpus file on disk produces a fresh index."""
    save_indexed_corpus(tmp_path, "npm", ["old-a"])
    index1 = load_indexed_corpus(tmp_path, "npm")
    assert "old-a" in index1

    save_indexed_corpus(tmp_path, "npm", ["new-b"])
    index2 = load_indexed_corpus(tmp_path, "npm")
    assert "new-b" in index2
    assert index1 is not index2


# ── SymSpell delete-index acceleration (WO5.0.0-028) ──────────────────────


def test_delete_index_build_is_incremental_and_exact():
    """Queries stay exact while the chunked build advances; completion flips
    the serving path but never the results."""
    names = [f"pkg-{i:04d}" for i in range(200)] + ["pkg-0000a", "pkg-0001b"]
    incremental = CorpusIndex(names, delete_index_chunks=10)
    oracle = CorpusIndex(names, delete_index_chunks=0)

    assert incremental._delete_cursor == 0
    for i in range(0, 40, 10):
        q = f"pkg-{i:04d}"
        assert incremental.near_matches(q, max_distance=2.0) == oracle.near_matches(q, max_distance=2.0)
    assert incremental._delete_cursor is not None
    assert len(incremental._delete_index) < len(oracle._delete_index)

    for i in range(0, 200, 7):
        q = f"pkg-{i:04d}x"
        assert incremental.near_matches(q, max_distance=2.0) == oracle.near_matches(q, max_distance=2.0)
    assert incremental._delete_cursor is None
    assert len(incremental._delete_index) == len(oracle._delete_index)


def test_finish_delete_index_completes_build():
    names = [f"n{i}" for i in range(50)]
    index = CorpusIndex(names, delete_index_chunks=4)
    index.finish_delete_index()
    assert index._delete_cursor is None
    # A query served purely by the delete index matches the trie oracle.
    oracle = CorpusIndex(names, delete_index_chunks=1 << 30)  # never completes
    for q in ("n1", "n49", "n25x", "zz"):
        assert index.near_matches(q, max_distance=2.0) == oracle.near_matches(q, max_distance=2.0)


def test_keyboard_queries_do_not_advance_build():
    index = CorpusIndex(["react", "reqct"], delete_index_chunks=1)
    assert index.near_matches("reavt", max_distance=1.0, use_keyboard=True) == [("react", 0.5), ("reqct", 1.0)]
    assert index._delete_cursor == 0


def test_prewarm_probe_counts_and_force_builds(tmp_path: Path, monkeypatch):
    from picosentry.scan.rules import typosquat as typo_mod

    (tmp_path / "package.json").write_text(
        json.dumps({"name": "t", "dependencies": {f"d{i}": "^1" for i in range(12)}})
    )
    assert typo_mod._npm_dep_probe(tmp_path) >= 12

    save_indexed_corpus(tmp_path, "npm", [f"pkg-{i}" for i in range(40)])
    monkeypatch.setattr(typo_mod, "_prewarmed", set())
    typo_mod.prewarm_typosquat_indexes(tmp_path, tmp_path)
    index = load_indexed_corpus(tmp_path, "npm", BUILTIN_TOP_100)
    assert index._delete_cursor is None
    assert (str(tmp_path), "npm") in typo_mod._prewarmed

    # Below the dep threshold nothing is force-built.
    small = tmp_path / "small"
    small.mkdir()
    (small / "package.json").write_text(json.dumps({"name": "t", "dependencies": {"left-pad": "^1"}}))
    assert typo_mod._npm_dep_probe(small) < typo_mod._PREWARM_DEP_THRESHOLD
