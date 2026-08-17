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

_MIN_PREFILTER_LITERAL = 3


def _extract_required_literals(parsed: list) -> tuple[tuple[str, ...], ...]:
    """Derive necessary-condition literal groups from a parsed regex (WO4.0.0-016).

    Returns groups where EVERY group must have at least one alternative present
    (case-insensitively) for the pattern to possibly match — a cheap substring
    prefilter that lets ``evaluate`` skip the full regex for most rules on most
    text. Conservative by construction:

    - Only ASCII literal runs of length >= 3 are used; everything else
      (char classes, ``.``, backrefs, optional repeats, ...) contributes NO
      constraint, so an unanalyzable rule simply always runs.
    - Literal runs never span non-literal gaps: ``you\\s+are`` yields two
      literals (``you``, ``are``), never the false ``youare``.
    - A mandatory repeat (``{1,}``-style) recurses into its subpattern; an
      optional one contributes nothing.
    - An alternation contributes ONE any-of group: the union of every literal
      of every branch. Sound because any match realizes ALL literals of one
      branch, so at least one union literal must be present. If any branch
      extracts no literal at all, the alternation contributes nothing.
    """
    groups: list[tuple[str, ...]] = []

    def _usable_literals(seq: list) -> list[str]:
        """All >=3-char ASCII literals in seq's own structure (no recursing
        into nested constructs that may be optional)."""
        run: list[str] = []
        found: list[str] = []
        for op, av in seq:
            if op is _sre_parse.LITERAL:
                run.append(chr(av))
                continue
            if run:
                found.append("".join(run))
                run = []
        if run:
            found.append("".join(run))
        return [lit for lit in found if len(lit) >= _MIN_PREFILTER_LITERAL and lit.isascii()]

    def _walk_sequence(seq: list) -> None:
        run: list[str] = []

        def _flush() -> None:
            if run:
                literal = "".join(run)
                if len(literal) >= _MIN_PREFILTER_LITERAL and literal.isascii():
                    groups.append((literal.lower(),))
                run.clear()

        for op, av in seq:
            if op is _sre_parse.LITERAL:
                run.append(chr(av))
                continue
            _flush()
            if op is _sre_parse.BRANCH:
                branches = av[1]
                union: set[str] = set()
                usable = bool(branches)
                for branch in branches:
                    branch_literals = _usable_literals(branch)
                    if not branch_literals:
                        usable = False  # a branch with no literals -> OR unconstrained
                        break
                    union.update(lit.lower() for lit in branch_literals)
                if usable and union:
                    groups.append(tuple(sorted(union)))
            elif op in (_sre_parse.MAX_REPEAT, _sre_parse.MIN_REPEAT):
                if av[0] >= 1:  # mandatory occurrence
                    _walk_sequence(av[2])
            elif op is _sre_parse.SUBPATTERN:
                _walk_sequence(av[-1])
            # IN, ANY, AT, CATEGORY, GROUPREF, ASSERT, ...: no constraint.
        _flush()

    _walk_sequence(parsed)
    return tuple(groups)


class RuleEngine:
    def __init__(self, rules_dir: Path | None = None) -> None:
        self._rules_dir = rules_dir
        self._rules: list[Rule] = []
        self._compiled: dict[str, re.Pattern[str]] = {}
        self._prefilter: dict[str, tuple[tuple[str, ...], ...]] = {}
        self._corpus_hash = "no-rules-loaded"
        self._rules_expected: int = 0
        self._load_errors: list[str] = []
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
        if loaded < expected_count:
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

        for rule in self._rules:
            compiled = self._compiled.get(rule.id)
            if compiled is None:
                continue
            groups = self._prefilter.get(rule.id)
            if groups:
                # Necessary-condition prefilter: every group must have at least
                # one alternative present or the regex cannot match — skip the
                # (much more expensive) full scan (WO4.0.0-016).
                passed = True
                for alternatives in groups:
                    if not any(alt in lowered for alt in alternatives):
                        passed = False
                        break
                if not passed:
                    continue
            match = compiled.search(text)
            if match:
                matches.append((rule, match))

        return matches
