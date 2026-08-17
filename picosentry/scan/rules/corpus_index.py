from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from pathlib import Path

from .typosquat_utils import _is_keyboard_adjacent, load_corpus_for_ecosystem

logger = logging.getLogger("picosentry.corpus_index")

# In-process cache for loaded corpus indexes.  The key includes the resolved
# corpus path, ecosystem, built-in priority list, and the corpus file's mtime
# and size so that updates on disk (e.g. ``picosentry update``) are picked up
# without restarting the process.
_index_cache: dict[tuple[str, str, tuple[str, ...], float | None, int | None], CorpusIndex] = {}


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

    Very short query names (1-3 characters) are matched only against the
    ``priority_names`` subset.  This prevents obscure short packages in the
    expanded corpus from generating false-positive typosquats against legitimate
    short names (e.g. npm's ``tap`` matching ``asap``), while still catching
    typosquats of well-known short packages carried in the built-in list
    (e.g. ``nx1`` for ``next`` or ``jin`` for ``gin``).
    """

    def __init__(
        self,
        names: Iterable[str],
        *,
        priority_names: Iterable[str] | None = None,
    ) -> None:
        priority = frozenset({name for name in (priority_names or ()) if isinstance(name, str)})
        self._priority_names = priority
        merged = {name for name in names if isinstance(name, str)}
        merged.update(priority)
        self._names = sorted(merged)
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

    @property
    def priority_names(self) -> frozenset[str]:
        return self._priority_names

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

        # Short queries are restricted to the curated priority set to avoid
        # false positives against obscure short names in the expanded corpus.
        short_query = query_len < 4

        matches: list[tuple[str, float]] = []
        for length in range(min_len, max_len + 1):
            root = self._tries.get(length)
            if root is None:
                continue
            if use_keyboard:
                self._search_keyboard(root, name, max_distance, matches)
            else:
                self._search_edit(root, name, max_distance, matches)

        if short_query:
            # Restrict short queries to the curated priority set and apply extra
            # guards to avoid collisions among short names:
            #   - 3-char vs 3-char: require distance <= 1 (tap vs yup at 2 is noise).
            #   - 3-char vs 4+ char: require the first character to match so we
            #     still catch nx1->next but avoid tap->gsap.
            matches = [
                m
                for m in matches
                if m[0] in self._priority_names
                and not (len(m[0]) < 4 and m[1] > 1.0)
                and not (len(m[0]) >= 4 and not m[0].startswith(name[0]))
            ]

        matches.sort(key=lambda m: (m[1], m[0]))
        return matches

    def _search_edit(
        self,
        root: _TrieNode,
        query: str,
        max_distance: float,
        matches: list[tuple[str, float]],
    ) -> None:
        self._search_banded(root, query, max_distance, matches, use_keyboard=False)

    def _search_keyboard(
        self,
        root: _TrieNode,
        query: str,
        max_distance: float,
        matches: list[tuple[str, float]],
    ) -> None:
        self._search_banded(root, query, max_distance, matches, use_keyboard=True)

    def _search_banded(
        self,
        root: _TrieNode,
        query: str,
        max_distance: float,
        matches: list[tuple[str, float]],
        *,
        use_keyboard: bool,
    ) -> None:
        """Trie walk with halo-banded DP rows (WO4.0.0-014 perf fix).

        Only cells with ``|depth - j| <= int(max_distance) + 1`` are computed;
        everything else is the sentinel ``max_distance + 1``.  This is exact for
        every reported match: ``value(i, j) >= |i - j|``, so any cell (and every
        DP ancestor of a cell) with value <= max_distance lies inside the band,
        and any path through a sentinel cell evaluates to > max_distance and can
        never surface as a match.  Pruning decisions are therefore identical to
        the unbanded walk.
        """
        query_len = len(query)
        maxd = max_distance
        sentinel = maxd + 1
        band = int(maxd) + 1

        prev = [float(i) if i <= maxd else sentinel for i in range(query_len + 1)]
        stack: list[tuple[_TrieNode, list[float], int]] = [(root, prev, 0)]

        while stack:
            node, prev_row, depth = stack.pop()
            i = depth + 1
            for candidate in node.names:
                if candidate == query:
                    continue
                dist = prev_row[-1]
                if dist <= maxd:
                    matches.append((candidate, dist))

            lo = i - band
            if lo < 1:
                lo = 1
            hi = i + band
            if hi > query_len:
                hi = query_len

            for ch, child in node.children.items():
                cur = [sentinel] * (query_len + 1)
                cur[0] = i
                # Cell 0 (all deletions) is exact and can keep a shallow branch
                # alive even when every band cell exceeds maxd.
                row_min = min(sentinel, i)
                prev_j = prev_row[lo - 1]
                for j in range(lo, hi + 1):
                    pj = prev_row[j]
                    val = pj + 1
                    deletion = cur[j - 1] + 1
                    if deletion < val:
                        val = deletion
                    if ch == query[j - 1]:
                        substitution = prev_j
                    elif use_keyboard and _is_keyboard_adjacent(ch, query[j - 1]):
                        substitution = prev_j + 0.5
                    else:
                        substitution = prev_j + 1
                    if substitution < val:
                        val = substitution
                    cur[j] = val
                    if val < row_min:
                        row_min = val
                    prev_j = pj
                if row_min <= maxd:
                    stack.append((child, cur, i))


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


def _cache_key(
    corpus_dir: Path,
    ecosystem: str,
    builtin_list: list[str] | None,
) -> tuple[str, str, tuple[str, ...], float | None, int | None]:
    corpus_file = corpus_dir / f"{ecosystem}_top_packages.json"
    if corpus_file.is_file():
        stat = corpus_file.stat()
        return (
            str(corpus_file.resolve()),
            ecosystem,
            tuple(sorted(builtin_list or ())),
            stat.st_mtime,
            stat.st_size,
        )
    return (
        str(corpus_dir.resolve()),
        ecosystem,
        tuple(sorted(builtin_list or ())),
        None,
        None,
    )


def load_indexed_corpus(
    corpus_dir: Path,
    ecosystem: str,
    builtin_list: list[str] | None = None,
) -> CorpusIndex:
    """Load a corpus and return it as a ``CorpusIndex``.

    This is the indexed replacement for ``load_corpus_for_ecosystem``.
    Callers that still need a raw ``set`` can use ``load_corpus_for_ecosystem``.

    The built-in list is treated as the curated priority set, so short-name
    queries are only matched against these well-known packages.  This keeps
    expanded corpuses from generating short-name false positives.

    The result is cached per process based on the corpus file identity
    (resolved path, mtime, size) and the built-in list, so repeated scans
    avoid rebuilding the trie.
    """
    key = _cache_key(corpus_dir, ecosystem, builtin_list)
    cached = _index_cache.get(key)
    if cached is not None:
        return cached

    corpus_set = load_corpus_for_ecosystem(corpus_dir, ecosystem, builtin_list)
    index = CorpusIndex(corpus_set, priority_names=builtin_list)
    _index_cache[key] = index
    logger.debug("Loaded and cached %s corpus (%d names)", ecosystem, len(index))
    return index


def save_indexed_corpus(corpus_dir: Path, ecosystem: str, names: Iterable[str]) -> Path:
    """Write a corpus JSON file for the given ecosystem.

    Returns the path written.  This helper is used by the update command.
    """
    corpus_file = corpus_dir / f"{ecosystem}_top_packages.json"
    corpus_file.parent.mkdir(parents=True, exist_ok=True)
    corpus_list = sorted({name for name in names if isinstance(name, str)})
    corpus_file.write_text(json.dumps(corpus_list, indent=4, ensure_ascii=False), encoding="utf-8")
    return corpus_file
