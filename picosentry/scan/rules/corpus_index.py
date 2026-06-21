from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from pathlib import Path

from .typosquat_utils import _is_keyboard_adjacent, load_corpus_for_ecosystem

logger = logging.getLogger("picosentry.corpus_index")


class _TrieNode:
    __slots__ = ("children", "names")

    def __init__(self) -> None:
        self.children: dict[str, _TrieNode] = {}
        self.names: list[str] = []


class CorpusIndex:
    """Fast, deterministic index for typosquat/dep-confusion corpus lookups.

    Internally the corpus is split into length buckets, and each bucket is
    stored in a trie.  For each query we walk the trie(s) whose name length is
    within ``max_distance`` of the query length while maintaining the classic
    dynamic-programming row for edit distance (or keyboard distance).  Branches
    whose entire row exceeds ``max_distance`` are pruned, so for small
    thresholds the search is far faster than a brute-force ``O(n·m)`` scan over
    the full corpus.

    Length-bucketing is used as the primary filter because an edit-distance
    match cannot differ in length by more than the distance threshold.  The trie
    automaton is exact: no valid near-match is dropped.
    """

    def __init__(self, names: Iterable[str]) -> None:
        self._names = sorted({name for name in names if isinstance(name, str)})
        self._tries: dict[int, _TrieNode] = {}
        for name in self._names:
            self._insert(name)

    def __len__(self) -> int:
        return len(self._names)

    def __contains__(self, name: str) -> bool:
        return name in self._names

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(self._names)

    def _insert(self, name: str) -> None:
        length = len(name)
        root = self._tries.setdefault(length, _TrieNode())
        node = root
        for ch in name:
            node = node.children.setdefault(ch, _TrieNode())
        node.names.append(name)

    def near_matches(
        self,
        name: str,
        *,
        max_distance: float = 2.0,
        use_keyboard: bool = False,
    ) -> list[tuple[str, float]]:
        """Return corpus names within ``max_distance`` of ``name``.

        Results are sorted by (distance, name) for deterministic ordering.
        """
        if name.startswith("@"):
            return []

        query_len = len(name)
        max_dist_int = int(max_distance)
        min_len = max(0, query_len - max_dist_int)
        max_len = query_len + max_dist_int

        matches: list[tuple[str, float]] = []
        for length in range(min_len, max_len + 1):
            root = self._tries.get(length)
            if root is None:
                continue
            if use_keyboard:
                self._search_keyboard(root, name, max_distance, matches)
            else:
                self._search_edit(root, name, max_distance, matches)

        matches.sort(key=lambda m: (m[1], m[0]))
        return matches

    def _search_edit(
        self,
        root: _TrieNode,
        query: str,
        max_distance: float,
        matches: list[tuple[str, float]],
    ) -> None:
        query_len = len(query)
        maxd = max_distance
        # Initial row for empty trie prefix.
        prev = [float(i) if i <= maxd else maxd + 1 for i in range(query_len + 1)]
        stack: list[tuple[_TrieNode, list[float]]] = [(root, prev)]

        while stack:
            node, prev_row = stack.pop()
            for candidate in node.names:
                if candidate == query:
                    continue
                dist = prev_row[-1]
                if dist <= maxd:
                    matches.append((candidate, dist))

            for ch, child in node.children.items():
                cur = [0.0] * (query_len + 1)
                cur[0] = prev_row[0] + 1
                row_min = cur[0]
                for j, query_ch in enumerate(query, start=1):
                    insertions = prev_row[j] + 1
                    deletions = cur[j - 1] + 1
                    substitutions = prev_row[j - 1] + (0.0 if ch == query_ch else 1.0)
                    val = min(insertions, deletions)
                    if substitutions < val:
                        val = substitutions
                    cur[j] = val
                    if val < row_min:
                        row_min = val
                if row_min <= maxd:
                    stack.append((child, cur))

    def _search_keyboard(
        self,
        root: _TrieNode,
        query: str,
        max_distance: float,
        matches: list[tuple[str, float]],
    ) -> None:
        query_len = len(query)
        maxd = max_distance
        prev = [float(i) if i <= maxd else maxd + 1 for i in range(query_len + 1)]
        stack: list[tuple[_TrieNode, list[float]]] = [(root, prev)]

        while stack:
            node, prev_row = stack.pop()
            for candidate in node.names:
                if candidate == query:
                    continue
                dist = prev_row[-1]
                if dist <= maxd:
                    matches.append((candidate, dist))

            for ch, child in node.children.items():
                cur = [0.0] * (query_len + 1)
                cur[0] = prev_row[0] + 1
                row_min = cur[0]
                for j, query_ch in enumerate(query, start=1):
                    insertions = prev_row[j] + 1
                    deletions = cur[j - 1] + 1
                    if ch == query_ch:
                        sub_cost = 0.0
                    elif _is_keyboard_adjacent(ch, query_ch):
                        sub_cost = 0.5
                    else:
                        sub_cost = 1.0
                    substitutions = prev_row[j - 1] + sub_cost
                    val = min(insertions, deletions)
                    if substitutions < val:
                        val = substitutions
                    cur[j] = val
                    if val < row_min:
                        row_min = val
                if row_min <= maxd:
                    stack.append((child, cur))


def check_typosquat_against_index(
    dep_name: str,
    index: CorpusIndex,
    max_distance: float = 2.0,
    use_keyboard: bool = False,
) -> list[tuple[str, float]]:
    """Drop-in replacement for ``check_typosquat`` that uses an indexed corpus.

    This function exists so callers can build or load the ``CorpusIndex`` once
    per scan and reuse it for every dependency, rather than paying the
    ``O(n·m)`` brute-force cost on each call.
    """
    return [
        (name, dist)
        for name, dist in index.near_matches(dep_name, max_distance=max_distance, use_keyboard=use_keyboard)
        if name != dep_name
    ]


def load_indexed_corpus(
    corpus_dir: Path,
    ecosystem: str,
    builtin_list: list[str] | None = None,
) -> CorpusIndex:
    """Load a corpus and return it as a ``CorpusIndex``.

    This is the indexed replacement for ``load_corpus_for_ecosystem``.
    Callers that still need a raw ``set`` can use ``load_corpus_for_ecosystem``.
    """
    corpus_set = load_corpus_for_ecosystem(corpus_dir, ecosystem, builtin_list)
    return CorpusIndex(corpus_set)


def save_indexed_corpus(corpus_dir: Path, ecosystem: str, names: Iterable[str]) -> Path:
    """Write a corpus JSON file for the given ecosystem.

    Returns the path written.  This helper is used by the update command.
    """
    corpus_file = corpus_dir / f"{ecosystem}_top_packages.json"
    corpus_file.parent.mkdir(parents=True, exist_ok=True)
    corpus_list = sorted({name for name in names if isinstance(name, str)})
    corpus_file.write_text(json.dumps(corpus_list, indent=4, ensure_ascii=False), encoding="utf-8")
    return corpus_file
