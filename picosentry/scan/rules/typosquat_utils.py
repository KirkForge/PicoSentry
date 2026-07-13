from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger("picosentry.typosquat_utils")


_KEYBOARD_ADJ: dict[str, set[str]] = {
    "q": {"w", "a"},
    "w": {"q", "e", "a", "s"},
    "e": {"w", "r", "s", "d"},
    "r": {"e", "t", "d", "f"},
    "t": {"r", "y", "f", "g"},
    "y": {"t", "u", "g", "h"},
    "u": {"y", "i", "h", "j"},
    "i": {"u", "o", "j", "k"},
    "o": {"i", "p", "k", "l"},
    "p": {"o", "l"},
    "a": {"q", "w", "s", "z"},
    "s": {"w", "e", "a", "d", "z", "x"},
    "d": {"e", "r", "s", "f", "x", "c"},
    "f": {"r", "t", "d", "g", "c", "v"},
    "g": {"t", "y", "f", "h", "v", "b"},
    "h": {"y", "u", "g", "j", "b", "n"},
    "j": {"u", "i", "h", "k", "n", "m"},
    "k": {"i", "o", "j", "l", "m"},
    "l": {"o", "p", "k"},
    "z": {"a", "s", "x"},
    "x": {"s", "d", "z", "c"},
    "c": {"d", "f", "x", "v"},
    "v": {"f", "g", "c", "b"},
    "b": {"g", "h", "v", "n"},
    "n": {"h", "j", "b", "m"},
    "m": {"j", "k", "n"},
}


def edit_distance(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    if len(b) == 0:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            insertions = prev[j + 1] + 1
            deletions = curr[j] + 1
            substitutions = prev[j] + (ca != cb)
            curr.append(min(insertions, deletions, substitutions))
        prev = curr
    return prev[-1]


def keyboard_distance(a: str, b: str) -> float:
    if len(a) < len(b):
        a, b = b, a
    if len(b) == 0:
        return float(len(a))

    prev: list[float] = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr: list[float] = [i + 1]
        for j, cb in enumerate(b):
            insertion = prev[j + 1] + 1
            deletion = curr[j] + 1
            if ca == cb:
                substitution: float = prev[j]
            elif _is_keyboard_adjacent(ca, cb):
                substitution = prev[j] + 0.5
            else:
                substitution = prev[j] + 1
            curr.append(min(insertion, deletion, substitution))
        prev = curr
    return prev[-1]


def _is_keyboard_adjacent(a: str, b: str) -> bool:
    al = a.lower()
    bl = b.lower()
    if al == bl:
        return False
    return bl in _KEYBOARD_ADJ.get(al, set()) or al in _KEYBOARD_ADJ.get(bl, set())


def check_typosquat(
    dep_name: str,
    corpus: set[str],
    max_distance: float = 2.0,
    use_keyboard: bool = False,
    *,
    priority_names: set[str] | None = None,
) -> list[tuple[str, float]]:

    if dep_name.startswith("@"):
        return []

    distance_fn = keyboard_distance if use_keyboard else edit_distance

    name_len = len(dep_name)
    matches: list[tuple[str, float]] = []
    # Short queries are restricted to the curated priority set to stay
    # consistent with ``CorpusIndex.near_matches`` and avoid false positives
    # against obscure short names in large corpuses.
    short_query = name_len < 4
    priority = priority_names if priority_names is not None else corpus

    for popular in sorted(corpus):  # sorted for determinism
        if popular == dep_name:
            continue

        if short_query and popular not in priority:
            continue

        if abs(name_len - len(popular)) > max_distance:
            continue
        dist = distance_fn(dep_name, popular)
        if dist > max_distance:
            continue

        # Two very short names must differ by at most one character to avoid
        # unrelated 3-letter package collisions (e.g. npm's tap vs yup).
        if short_query and len(popular) < 4 and dist > 1.0:
            continue
        # A 3-character query against a 4+ character name only counts if the
        # first character matches; this catches nx1->next while avoiding
        # tap->gsap style collisions.
        if short_query and len(popular) >= 4 and not popular.startswith(dep_name[0]):
            continue

        matches.append((popular, dist))

    matches.sort(key=lambda m: (m[1], m[0]))
    return matches


def typosquat_severity_confidence(
    dep_name: str,
    match_name: str,
    distance: float,
) -> tuple:
    from ..models import Confidence, Severity

    min_len = min(len(dep_name), len(match_name))
    length_ratio = min_len / max(len(dep_name), len(match_name), 1)

    if min_len <= 4:
        if distance >= 2:
            return Severity.LOW, Confidence.LOW
        return Severity.MEDIUM, Confidence.MEDIUM

    if distance <= 1 and length_ratio >= 0.8:
        return Severity.HIGH, Confidence.HIGH
    if distance <= 2 and length_ratio >= 0.6:
        return Severity.MEDIUM, Confidence.MEDIUM
    return Severity.LOW, Confidence.LOW


def load_corpus_for_ecosystem(
    corpus_dir: Path,
    ecosystem: str,
    builtin_list: list[str] | None = None,
) -> set[str]:
    corpus_file = corpus_dir / f"{ecosystem}_top_packages.json"
    if corpus_file.is_file():
        try:
            data = json.loads(corpus_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return set(data)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(
                "Corpus file %s is corrupt (%s), falling back to built-in list.",
                corpus_file,
                e,
            )
    else:
        logger.info(
            "No corpus file at %s, using built-in fallback. Run 'picosentry update' to download.",
            corpus_file,
        )

    if builtin_list:
        return set(builtin_list)
    return set()
