from __future__ import annotations

import json
import logging
import threading
from collections.abc import Iterable
from itertools import combinations
from pathlib import Path

from .typosquat_utils import _is_keyboard_adjacent, load_corpus_for_ecosystem

logger = logging.getLogger("picosentry.corpus_index")

# In-process cache for loaded corpus indexes.  The key includes the resolved
# corpus path, ecosystem, built-in priority list, and the corpus file's mtime
# and size so that updates on disk (e.g. ``picosentry update``) are picked up
# without restarting the process. WO6.0.0-019: stale entries for the same
# logical identity (path + ecosystem + builtin_list) are evicted on insert
# (see load_indexed_corpus) so the long-lived daemon does not retain one index
# per update cycle.
# ponytail: ceiling — aggregate prewarm cost across all 7 ecosystems is
# ~412MB / ~11s for a polyglot dep-heavy repo (npm 3.07s/+124MB, pypi 2.91s/
# +94MB, go 1.60s/+69MB, cargo 0.26s/+7MB, maven 1.18s/+34MB, nuget 1.94s/
# +79MB, rubygems 0.13s/+5MB; measured 2026-08-18). All outside the per-rule
# 5s timebox. WO6.0.0-019 limits prewarm to detected ecosystems, so a
# 2-ecosystem scan pays ~6s/180MB instead of ~11s/412MB. Upgrade path:
# on-disk persisted delete-index in ``picosentry update`` if RSS bites.
_index_cache: dict[tuple[str, str, tuple[str, ...], float | None, int | None], CorpusIndex] = {}

# SymSpell-style delete-neighborhood acceleration (WO5.0.0-028).  For
# unit-cost Levenshtein with max_distance <= 2, candidates are generated via
# precomputed delete-variants instead of walking the trie: if two strings are
# within edit distance d, some delete-d variant of the query equals some
# delete-d variant of the corpus name, so a dictionary join over the variants
# finds every match.  Each candidate is then verified with an exact two-row
# Levenshtein, so results are identical to the trie walk.  Keyboard distance
# (0.5-cost substitutions) is NOT covered by that completeness argument and
# always uses the trie.
_SYMSPELL_MAX_DISTANCE = 2
# The delete index is built incrementally — one chunk of corpus names per
# non-keyboard query — so a cold corpus never charges the whole build to a
# single rule execution (the per-rule timebox is 5s) and small scans that
# never finish the build keep the trie's latency.
_DELETE_INDEX_CHUNKS = 16


def _levenshtein_within(a: str, b: str, max_distance: int) -> int:
    """Exact unit-cost Levenshtein, returning ``max_distance + 1`` when the
    distance exceeds ``max_distance``."""
    la = len(a)
    lb = len(b)
    if la - lb > max_distance or lb - la > max_distance:
        return max_distance + 1
    if la == 0:
        return lb if lb <= max_distance else max_distance + 1
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        ca = a[i - 1]
        cur = [i]
        append = cur.append
        row_min = i
        for j in range(1, lb + 1):
            val = prev[j] + 1
            deletion = cur[j - 1] + 1
            if deletion < val:
                val = deletion
            substitution = prev[j - 1] if ca == b[j - 1] else prev[j - 1] + 1
            if substitution < val:
                val = substitution
            append(val)
            if val < row_min:
                row_min = val
        if row_min > max_distance:
            return max_distance + 1
        prev = cur
    return prev[-1] if prev[-1] <= max_distance else max_distance + 1


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
        delete_index_chunks: int = _DELETE_INDEX_CHUNKS,
    ) -> None:
        priority = frozenset({name for name in (priority_names or ()) if isinstance(name, str)})
        self._priority_names = priority
        merged = {name for name in names if isinstance(name, str)}
        merged.update(priority)
        self._names = sorted(merged)
        self._tries: dict[int, _TrieNode] = {}
        for name in self._names:
            self._insert(name)
        # Incremental SymSpell build state.  Each non-keyboard query advances
        # the delete-index build by one chunk of corpus names and is served by
        # the exact trie until the build completes — no single query ever pays
        # the whole build, so the per-rule timebox cannot be blown by index
        # construction.  ``delete_index_chunks <= 0`` builds everything at
        # construction (used by tests to pin the accelerated path).
        self._delete_index: dict[str, str | list[str]] = {}
        self._delete_lock = threading.Lock()
        self._delete_step = (
            max(1, -(-len(self._names) // delete_index_chunks)) if delete_index_chunks > 0 else len(self._names)
        )
        self._delete_cursor = 0 if delete_index_chunks > 0 else None
        if delete_index_chunks <= 0:
            self._advance_delete_build(len(self._names))

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

        # Short queries are restricted to the curated priority set to avoid
        # false positives against obscure short names in the expanded corpus.
        short_query = query_len < 4

        matches: list[tuple[str, float]] = []
        if use_keyboard or max_dist_int > _SYMSPELL_MAX_DISTANCE:
            self._search_length_buckets(name, max_distance, use_keyboard, query_len, max_dist_int, matches)
        else:
            # Advance the incremental build; serve via the exact trie until
            # the delete index is complete, then switch to it.
            with self._delete_lock:
                if self._delete_cursor is not None:
                    self._advance_delete_build(self._delete_step)
                complete = self._delete_cursor is None
            if complete:
                self._search_deletes(self._delete_index, name, max_dist_int, matches)
            else:
                self._search_length_buckets(name, max_distance, False, query_len, max_dist_int, matches)

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

    def _search_length_buckets(
        self,
        query: str,
        max_distance: float,
        use_keyboard: bool,
        query_len: int,
        max_dist_int: int,
        matches: list[tuple[str, float]],
    ) -> None:
        min_len = max(0, query_len - max_dist_int)
        max_len = query_len + max_dist_int
        for length in range(min_len, max_len + 1):
            root = self._tries.get(length)
            if root is None:
                continue
            if use_keyboard:
                self._search_keyboard(root, query, max_distance, matches)
            else:
                self._search_edit(root, query, max_distance, matches)

    def finish_delete_index(self) -> None:
        """Complete the incremental delete-index build synchronously.

        Used by the scan engine's prewarm step so the one-time build cost
        lands outside the per-rule timebox instead of inside the first
        dependency-heavy rule execution.
        """
        with self._delete_lock:
            if self._delete_cursor is not None:
                self._advance_delete_build(len(self._names))

    def _advance_delete_build(self, step: int) -> None:
        """Index the delete-2 variants of the next ``step`` corpus names.

        Callers hold ``_delete_lock``.  Values are a single name (the common
        case) or a list when several corpus names share a variant; repeated
        letters can yield a duplicate variant, and the duplicate upsert is
        harmless because query-side candidates are a set.
        """
        # ponytail: memory is O(names·len²) — ~150 MB for the 5k-name npm
        # corpus; persist to disk in ``picosentry update`` if this ceiling bites.
        index = self._delete_index
        get = index.get
        names = self._names
        cursor = self._delete_cursor
        end = len(names) if cursor is None else min(len(names), cursor + step)
        for name in names[cursor:end]:
            n = len(name)
            for variant in [name] + [name[:i] + name[i + 1 :] for i in range(n)]:
                current = get(variant)
                if current is None:
                    index[variant] = name
                elif isinstance(current, str):
                    index[variant] = [current, name]
                else:
                    current.append(name)
            if n >= 2:
                for i, j in combinations(range(n), 2):
                    variant = name[:i] + name[i + 1 : j] + name[j + 1 :]
                    current = get(variant)
                    if current is None:
                        index[variant] = name
                    elif isinstance(current, str):
                        index[variant] = [current, name]
                    else:
                        current.append(name)
        self._delete_cursor = end if end < len(names) else None

    def _search_deletes(
        self,
        delete_index: dict[str, str | list[str]],
        query: str,
        max_dist_int: int,
        matches: list[tuple[str, float]],
    ) -> None:
        candidates: set[str] = set()
        update = candidates.update
        add = candidates.add
        get = delete_index.get
        n = len(query)
        for variant in [query] + [query[:i] + query[i + 1 :] for i in range(n)]:
            bucket = get(variant)
            if bucket is None:
                continue
            if isinstance(bucket, str):
                add(bucket)
            else:
                update(bucket)
        if max_dist_int >= 2 and n >= 2:
            for i, j in combinations(range(n), 2):
                bucket = get(query[:i] + query[i + 1 : j] + query[j + 1 :])
                if bucket is None:
                    continue
                if isinstance(bucket, str):
                    add(bucket)
                else:
                    update(bucket)
        for candidate in candidates:
            if candidate == query:
                continue
            dist = _levenshtein_within(query, candidate, max_dist_int)
            if dist <= max_dist_int:
                matches.append((candidate, float(dist)))

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
    avoid rebuilding the trie. WO6.0.0-019: stale entries (same path +
    ecosystem + builtin_list but an old mtime/size from a prior
    ``picosentry update``) are evicted on insert so the long-lived daemon
    does not retain one ~412MB index per update cycle.
    """
    key = _cache_key(corpus_dir, ecosystem, builtin_list)
    cached = _index_cache.get(key)
    if cached is not None:
        return cached

    # Evict stale entries for the same logical identity (path + ecosystem +
    # builtin_list) but an outdated (mtime, size). The cache key includes the
    # version, so an on-disk update produces a NEW key; without eviction the
    # old key's CorpusIndex stays strongly referenced and RSS grows by one
    # index per update cycle (WO6.0.0-019).
    identity = key[:3]
    stale = [k for k in _index_cache if k[:3] == identity and k != key]
    for k in stale:
        _index_cache.pop(k, None)

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
