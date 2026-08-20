from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path

import yaml

from picosentry.watch.types import Rule

logger = logging.getLogger("picowatch.rules")

# Keys Rule() actually consumes — anything else in a rule dict is a typo or drift.
_RULE_FIELDS = frozenset({"id", "category", "weight", "pattern", "description"})

try:  # Python 3.11+
    import re._parser as _sre_parse
except ImportError:  # Python 3.10
    import sre_parse as _sre_parse

_MIN_PREFILTER_LITERAL = 2
_MAX_PREFILTER_BRANCHES = 64
_MAX_CLASS_ALTERNATIVES = 32


def _class_alternatives(av) -> tuple[str, ...] | None:
    """Case-folded alternatives for a finite positive IN char class, else None.

    av is sre_parse's flat item list; a NEGATE or CATEGORY item (negated
    class, \\d, \\s) contributes no constraint. Sound only for explicit
    literals and small ranges. Alternatives are the lowercased char plus the
    lowercase of its uppercase (covers re.IGNORECASE matching of either case
    in lowered text).
    """
    chars: list[str] = []
    for op, arg in av:
        if op is _sre_parse.LITERAL:
            chars.append(chr(arg))
        elif op is _sre_parse.RANGE:
            chars.extend(chr(c) for c in range(arg[0], arg[1] + 1))
        else:
            return None
    if not 1 <= len(chars) <= _MAX_CLASS_ALTERNATIVES:
        return None
    alts = {c.lower() for c in chars} | {c.upper().lower() for c in chars}
    return tuple(sorted(alts))


def _extract_required_literals(parsed: list) -> tuple[tuple[tuple[str, ...], ...], ...]:
    """Derive necessary-condition branch conjunctions from a parsed regex.

    Returns a tuple of branches; each branch is a tuple of any-of groups;
    the pattern can only match if SOME branch has EVERY group satisfied
    (each group needs at least one alternative present, case-insensitively).
    A rule whose pattern is a plain sequence yields a single branch — the
    previous AND-of-union-groups shape. Splitting top-level alternations
    into OR-of-branch-ANDs is strictly stronger and still sound: any match
    realizes ALL literals of exactly one branch (WO5.0.0-029).

    Conservative by construction:

    - Only ASCII literal runs of length >= 2 are used; everything else
      (char classes, ``.``, backrefs, optional repeats, ...) contributes NO
      constraint, so an unanalyzable rule simply always runs — except
      finite positive char classes, which contribute their (folded) chars.
    - Literal runs never span non-literal gaps: ``you\\s+are`` yields two
      literals (``you``, ``are``), never the false ``youare``.
    - A mandatory repeat (``{1,}``-style) recurses into its subpattern; an
      optional one contributes nothing.
    - An alternation contributes alternatives covering every branch
      realization; if any branch extracts no constraint at all, that
      branch imposes nothing on the disjunction.
    """

    def _merge(branches: list[list[tuple[str, ...]]], variants: list[tuple[tuple[str, ...], ...]]) -> None:
        """Fold one nested construct's realization variants into every branch
        (cartesian); degrades to a single union group if the split explodes."""
        if not variants:
            return
        if len(branches) * len(variants) > _MAX_PREFILTER_BRANCHES:
            union = sorted({alt for variant in variants for group in variant for alt in group})
            for branch in branches:
                branch.append(tuple(union))
            return
        combined: list[list[tuple[str, ...]]] = []
        for branch in branches:
            for variant in variants:
                combined.append(branch + list(variant))
        branches[:] = combined

    def _walk_sequence(seq: list) -> list[tuple[tuple[str, ...], ...]]:
        """Conjunction-branch variants realizable by this sequence."""
        branches: list[list[tuple[str, ...]]] = [[]]

        def _flush(run: list[str]) -> None:
            if run:
                literal = "".join(run)
                if len(literal) >= _MIN_PREFILTER_LITERAL and literal.isascii():
                    for branch in branches:
                        branch.append((literal.lower(),))

        run: list[str] = []
        for op, av in seq:
            if op is _sre_parse.LITERAL:
                run.append(chr(av))
                continue
            _flush(run)
            run = []
            if op is _sre_parse.BRANCH:
                # A branch that realizes zero constraints makes the whole
                # alternation unconstrained — silently dropping only that
                # branch (the old `if v` filter) left the prefilter demanding
                # a literal the empty branch's matches cannot satisfy
                # (WO6.0.0-001: `(?:one|1)` demanded "one" and rejected
                # "priority 1"). If any branch walks to an empty realization,
                # contribute nothing.
                per_branch = [_walk_sequence(branch) for branch in av[1]]
                if any(not v for branch_variants in per_branch for v in branch_variants):
                    continue
                variants = [v for branch_variants in per_branch for v in branch_variants if v]
                _merge(branches, variants)
            elif op in (_sre_parse.MAX_REPEAT, _sre_parse.MIN_REPEAT):
                if av[0] >= 1:  # mandatory occurrence
                    sub = _walk_sequence(av[2])
                    if any(not v for v in sub):
                        continue
                    _merge(branches, [v for v in sub if v])
            elif op is _sre_parse.SUBPATTERN:
                sub = _walk_sequence(av[-1])
                if any(not v for v in sub):
                    continue
                _merge(branches, [v for v in sub if v])
            elif op is _sre_parse.IN:
                alts = _class_alternatives(av)
                if alts is not None:
                    for branch in branches:
                        branch.append(alts)
            # ANY, AT, CATEGORY, GROUPREF, ASSERT, ...: no constraint.
        _flush(run)
        return [tuple(branch) for branch in branches]

    result = [branch for branch in _walk_sequence(parsed) if branch]
    if not result:
        return ()
    return tuple(result)


class RuleEngine:
    def __init__(self, rules_dir: Path | None = None, allowed_categories: frozenset[str] | None = None) -> None:
        self._rules_dir = rules_dir
        self._rules: list[Rule] = []
        self._compiled: dict[str, re.Pattern[str]] = {}
        self._prefilter: dict[str, tuple[tuple[tuple[str, ...], ...], ...]] = {}
        self._corpus_hash = "no-rules-loaded"
        self._rules_expected: int = 0
        self._load_errors: list[str] = []
        self._allowed_categories = allowed_categories
        if rules_dir and rules_dir.exists():
            self._load_rules(rules_dir)

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    @property
    def corpus_hash(self) -> str:
        return self._corpus_hash

    @property
    def rules_loaded(self) -> int:
        return len(self._rules)

    @property
    def rules_expected(self) -> int:
        return self._rules_expected

    @property
    def load_errors(self) -> list[str]:
        return list(self._load_errors)

    def _load_rules(self, rules_dir: Path) -> None:
        yaml_files = sorted(rules_dir.rglob("*.yaml")) + sorted(rules_dir.rglob("*.yml"))
        raw_rules: list[Rule] = []
        hash_parts: list[bytes] = []
        expected_count: int = 0

        for yaml_file in yaml_files:
            try:
                content = yaml_file.read_text(encoding="utf-8")
                hash_parts.append(content.encode("utf-8"))
                data = yaml.safe_load(content)
                if data is None:
                    continue

                rule_dicts = data if isinstance(data, list) else [data]
                for rd in rule_dicts:
                    if not isinstance(rd, dict):
                        continue
                    expected_count += 1
                    unknown_keys = set(rd) - _RULE_FIELDS
                    if unknown_keys:
                        msg = f"Unknown key(s) {', '.join(sorted(unknown_keys))} in rule in {yaml_file.name}"
                        logger.warning(msg)
                        self._load_errors.append(msg)
                    try:
                        rule = Rule(
                            id=rd["id"],
                            category=rd["category"],
                            weight=float(rd.get("weight", 0.5)),
                            pattern=rd["pattern"],
                            description=rd.get("description", ""),
                        )
                        raw_rules.append(rule)
                    except (KeyError, ValueError, TypeError) as e:
                        msg = f"Invalid rule in {yaml_file.name}: {e}"
                        logger.warning(msg)
                        self._load_errors.append(msg)
            except yaml.YAMLError as e:
                msg = f"YAML parse error in {yaml_file.name}: {e}"
                logger.warning(msg)
                self._load_errors.append(msg)
                continue
            except Exception as e:
                msg = f"Error loading rule file {yaml_file.name}: {e}"
                logger.warning(msg)
                self._load_errors.append(msg)
                continue

        raw_rules.sort(key=lambda r: r.id)
        # Drop duplicate ids: _compiled is keyed by rule.id, so a collision
        # would make every rule sharing that id evaluate with the last-compiled
        # pattern (silent misfire). Keep the first, record the rest as errors.
        deduped: list[Rule] = []
        seen: set[str] = set()
        for rule in raw_rules:
            if rule.id in seen:
                msg = f"Duplicate rule id {rule.id!r} ignored (first definition wins)"
                logger.warning(msg)
                self._load_errors.append(msg)
                continue
            seen.add(rule.id)
            deduped.append(rule)
        self._rules = deduped
        if self._allowed_categories is not None:
            # Tenant profile selection (WO4.0.0-023): keep only the chosen
            # categories. rules_expected still counts the full corpus so the
            # coverage warning below only fires for genuine load failures.
            deduped = [r for r in deduped if r.category in self._allowed_categories]
            self._rules = deduped
        self._rules_expected = expected_count

        for rule in self._rules:
            try:
                self._compiled[rule.id] = re.compile(rule.pattern, re.IGNORECASE | re.DOTALL)
                self._prefilter[rule.id] = _extract_required_literals(_sre_parse.parse(rule.pattern))
            except re.error as e:
                msg = f"Regex compile error for rule {rule.id}: {e}"
                logger.warning(msg)
                self._load_errors.append(msg)

        if hash_parts:
            hasher = hashlib.sha256()
            for part in hash_parts:
                hasher.update(part)
            self._corpus_hash = hasher.hexdigest()[:16]
        else:
            self._corpus_hash = "no-rules-loaded"

        loaded = len(self._rules)
        errors = len(self._load_errors)
        if self._allowed_categories is not None:
            logger.info("Loaded %d rules for profile categories %s", loaded, sorted(self._allowed_categories))
        elif loaded < expected_count:
            logger.warning(
                "Rule coverage gap: loaded %d/%d rules (%d errors). Rule IDs with issues: %s",
                loaded,
                expected_count,
                errors,
                ", ".join(self._load_errors[:5]) if self._load_errors else "none",
            )
        logger.info("Loaded %d rules (expected %d, %d compile/load errors)", loaded, expected_count, errors)

    def evaluate(self, text: str) -> list[tuple[Rule, re.Match[str]]]:
        matches: list[tuple[Rule, re.Match[str]]] = []
        lowered = text.lower()
        found: dict[str, bool] = {}

        def _present(alt: str) -> bool:
            hit = found.get(alt)
            if hit is None:
                hit = found[alt] = alt in lowered
            return hit

        for rule in self._rules:
            compiled = self._compiled.get(rule.id)
            if compiled is None:
                continue
            branches = self._prefilter.get(rule.id)
            if branches:
                # Necessary-condition prefilter: some branch must have every
                # any-of group satisfied or the regex cannot match — skip the
                # (much more expensive) full scan (WO4.0.0-016, WO5.0.0-029).
                # Alternatives are shared across rules, so each distinct
                # substring is scanned once per evaluate call.
                passed = False
                for branch in branches:
                    group_ok = True
                    for group in branch:
                        if not any(_present(alt) for alt in group):
                            group_ok = False
                            break
                    if group_ok:
                        passed = True
                        break
                if not passed:
                    continue
            match = compiled.search(text)
            if match:
                matches.append((rule, match))

        return matches
