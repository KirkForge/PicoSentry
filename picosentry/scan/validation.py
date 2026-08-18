from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("picosentry.validation")

# Label taxonomy emitted by the corpus generators
# (scripts/generate_corpus_fixtures.py, scripts/expand_corpus_to_6k.py).
# Semantic labels describe the attack technique of a *positive* fixture;
# the loader normalizes them to the "positive" expectation. Labels outside
# the taxonomy are rejected (fixture skipped with a warning).
POSITIVE_LABELS = frozenset({"positive", "typosquat", "obfuscation", "dep_confusion", "cve", "multi_attack"})


def known_rule_ids() -> frozenset[str]:
    """All rule ids the default engine can emit (incl. campaign matchers).

    Used by the loader to flag fixtures that expect a rule id which does
    not exist — the L2-CVE-001 / L2-NPM-OBFS-001 class of authoring bug
    that silently registers as recall loss.
    """
    from .rules import RULE_INFO

    ids = set(RULE_INFO)
    try:
        from .campaigns import iter_campaigns

        ids.update(c.rule_id for c in iter_campaigns())
    except Exception:  # pragma: no cover - campaign loading is best-effort here
        logger.debug("Campaign rule ids unavailable for known-rule check", exc_info=True)
    return frozenset(ids)


@dataclass(frozen=True)
class FindingAssertion:
    """Per-finding gate for a fixture (opt-in via fixture.json).

    Mirrors a subset of :class:`picosentry.scan.models.Finding` fields. A
    positive fixture that opts into ``expected_findings`` must produce at
    least one ``Finding`` matching every assertion; a fixture that opts
    into ``unexpected_findings`` must produce no ``Finding`` matching any
    assertion. All fields are optional except ``rule_id``; missing fields
    match any value on the finding.
    """

    rule_id: str
    package: str = ""
    ecosystem: str = ""
    file_contains: str = ""
    evidence_contains: str = ""
    line: int | None = None


@dataclass(frozen=True)
class FixtureSpec:
    path: Path
    label: str  # "positive" | "negative"
    expected_rule_ids: tuple[str, ...] = ()
    description: str = ""
    # Opt-in per-finding gates (added in v2.1; default to no-op for
    # backward compatibility with fixtures authored before the schema
    # extension).
    expected_findings: tuple[FindingAssertion, ...] = ()
    unexpected_findings: tuple[FindingAssertion, ...] = ()
    forbidden_rule_ids: tuple[str, ...] = ()
    strict: bool = False

    @property
    def name(self) -> str:
        return self.path.name


def _matches_finding(finding: Any, assertion: FindingAssertion, *, seen: set | None = None) -> bool:
    """Return True iff *finding* matches *assertion*.

    Fields that are empty/None in *assertion* are wildcards. The optional
    *seen* set is used to dedupe findings by their fingerprint
    (``(rule_id, ecosystem, package, file)``) — callers that iterate
    multiple assertions should pass the same set to avoid double-counting
    the same finding against multiple assertions.
    """
    if assertion.rule_id != finding.rule_id:
        return False
    fp = finding.fingerprint()
    if seen is not None:
        if fp in seen:
            return False
        seen.add(fp)
    if assertion.package and finding.package != assertion.package:
        return False
    if assertion.ecosystem and finding.ecosystem != assertion.ecosystem:
        return False
    if assertion.file_contains and assertion.file_contains not in finding.file:
        return False
    if assertion.evidence_contains and assertion.evidence_contains not in finding.evidence:
        return False
    return not (assertion.line is not None and finding.line != assertion.line)


def _as_finding_assertion(raw: object) -> FindingAssertion:
    """Coerce a JSON object from ``fixture.json`` into a :class:`FindingAssertion`.

    Raises ``ValueError`` on missing ``rule_id`` or wrong field types so
    the caller can surface a useful error in the loader.
    """
    if not isinstance(raw, dict):
        raise ValueError(f"finding assertion must be an object, got {type(raw).__name__}")
    rule_id = raw.get("rule_id")
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError("finding assertion requires a non-empty string 'rule_id'")
    line_raw = raw.get("line")
    line: int | None
    if line_raw is None:
        line = None
    elif isinstance(line_raw, int) and not isinstance(line_raw, bool):
        line = line_raw
    else:
        raise ValueError(f"finding assertion 'line' must be an integer or null, got {line_raw!r}")
    return FindingAssertion(
        rule_id=rule_id,
        package=str(raw.get("package", "") or ""),
        ecosystem=str(raw.get("ecosystem", "") or ""),
        file_contains=str(raw.get("file_contains", "") or ""),
        evidence_contains=str(raw.get("evidence_contains", "") or ""),
        line=line,
    )


@dataclass(frozen=True)
class RuleMetrics:
    rule_id: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        if denom == 0:
            return 0.0
        return self.true_positives / denom

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        if denom == 0:
            return 0.0
        return self.true_positives / denom

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
        }


@dataclass(frozen=True)
class ValidationReport:
    rule_metrics: tuple[RuleMetrics, ...] = ()
    total_fixtures: int = 0
    total_positive: int = 0
    total_negative: int = 0
    fixture_results: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
    """(fixture_name, "PASS" | "FAIL", (missing_rule_ids_or_unexpected_rule_ids,))"""
    unknown_rule_expectations: tuple[tuple[str, str], ...] = ()
    """(fixture_name, unknown_rule_id) — expectations against rule ids that
    don't exist; each one is guaranteed recall loss, so surface it."""
    skipped_fixtures: int = 0
    """Fixture dirs whose fixture.json failed to load (malformed JSON, unknown
    label, bad assertions). They are excluded from every metric above — the
    count keeps the shrunken denominator visible (WO5.0.0-016)."""

    @property
    def mean_precision(self) -> float:
        if not self.rule_metrics:
            return 0.0
        return sum(m.precision for m in self.rule_metrics) / len(self.rule_metrics)

    @property
    def mean_recall(self) -> float:
        if not self.rule_metrics:
            return 0.0
        return sum(m.recall for m in self.rule_metrics) / len(self.rule_metrics)

    def to_dict(self) -> dict:
        return {
            "total_fixtures": self.total_fixtures,
            "total_positive": self.total_positive,
            "total_negative": self.total_negative,
            "skipped_fixtures": self.skipped_fixtures,
            "mean_precision": round(self.mean_precision, 4),
            "mean_recall": round(self.mean_recall, 4),
            "rule_metrics": [
                {
                    "rule_id": m.rule_id,
                    "true_positives": m.true_positives,
                    "false_positives": m.false_positives,
                    "false_negatives": m.false_negatives,
                    "precision": round(m.precision, 4),
                    "recall": round(m.recall, 4),
                }
                for m in sorted(self.rule_metrics, key=lambda r: r.rule_id)
            ],
            "fixture_results": [
                {"fixture": name, "outcome": outcome, "details": list(details)}
                for name, outcome, details in self.fixture_results
            ],
            "unknown_rule_expectations": [
                {"fixture": name, "rule_id": rule_id} for name, rule_id in self.unknown_rule_expectations
            ],
        }

    def to_text(self) -> str:
        lines: list[str] = []
        lines.append("PicoSentry validation report")
        lines.append("=" * 60)
        lines.append(
            f"fixtures: {self.total_fixtures} (positive: {self.total_positive}, negative: {self.total_negative})"
        )
        if self.skipped_fixtures:
            lines.append(f"skipped fixtures: {self.skipped_fixtures} (excluded from metrics)")
        lines.append(f"mean precision: {self.mean_precision:.2%}")
        lines.append(f"mean recall:    {self.mean_recall:.2%}")
        if self.unknown_rule_expectations:
            lines.append("")
            lines.append(f"unknown expected_rule_ids: {len(self.unknown_rule_expectations)}")
            for name, rule_id in self.unknown_rule_expectations:
                lines.append(f"  {name}: expects nonexistent rule {rule_id}")
        lines.append("")
        lines.append("Per-rule metrics:")
        lines.append(f"  {'rule_id':<28} {'TP':>4} {'FP':>4} {'FN':>4} {'precision':>10} {'recall':>8}")
        lines.extend(
            f"  {m.rule_id:<28} {m.true_positives:>4} {m.false_positives:>4} "
            f"{m.false_negatives:>4} {m.precision:>10.2%} {m.recall:>8.2%}"
            for m in sorted(self.rule_metrics, key=lambda r: r.rule_id)
        )
        lines.append("")
        lines.append("Per-fixture outcome:")
        for name, outcome, details in self.fixture_results:
            detail_str = ", ".join(details) if details else "—"
            lines.append(f"  [{outcome}] {name:<32} {detail_str}")
        return "\n".join(lines) + "\n"

    @property
    def passes(self) -> bool:
        return all(outcome == "PASS" for _, outcome, _ in self.fixture_results)


def _load_fixture(path: Path) -> FixtureSpec | None:
    spec_path = path / "fixture.json"
    if not spec_path.is_file():
        return None
    try:
        data = json.loads(spec_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Skipping malformed fixture %s: %s", path, exc)
        return None
    raw_label = str(data.get("label", "")).lower()
    if raw_label in POSITIVE_LABELS:
        label = "positive"
    elif raw_label == "negative":
        label = "negative"
    else:
        logger.warning(
            "Fixture %s: label must be a known category (%s) or 'negative', got %r",
            path,
            "|".join(sorted(POSITIVE_LABELS)),
            raw_label,
        )
        return None
    try:
        expected_findings = tuple(_as_finding_assertion(e) for e in data.get("expected_findings", ()))
        unexpected_findings = tuple(_as_finding_assertion(e) for e in data.get("unexpected_findings", ()))
    except ValueError as exc:
        logger.warning("Fixture %s: %s", path, exc)
        return None
    forbidden_raw = data.get("forbidden_rule_ids", ())
    if not isinstance(forbidden_raw, (list, tuple)) or not all(isinstance(r, str) for r in forbidden_raw):
        logger.warning("Fixture %s: 'forbidden_rule_ids' must be a list of strings", path)
        return None
    strict_raw = data.get("strict", False)
    if not isinstance(strict_raw, bool):
        logger.warning("Fixture %s: 'strict' must be a boolean", path)
        return None
    return FixtureSpec(
        path=path,
        label=label,
        expected_rule_ids=tuple(data.get("expected_rule_ids", ())),
        description=data.get("description", ""),
        expected_findings=expected_findings,
        unexpected_findings=unexpected_findings,
        forbidden_rule_ids=tuple(forbidden_raw),
        strict=strict_raw,
    )


def _discover_fixtures_with_skips(validation_root: Path) -> tuple[list[FixtureSpec], int]:
    """Discover fixtures, counting dirs whose fixture.json failed to load."""
    if not validation_root.is_dir():
        return [], 0
    fixtures: list[FixtureSpec] = []
    skipped = 0
    for sub in ("positive", "negative"):
        sub_root = validation_root / sub
        if not sub_root.is_dir():
            continue
        for entry in sorted(sub_root.iterdir()):
            if not entry.is_dir() or not (entry / "fixture.json").is_file():
                continue
            spec = _load_fixture(entry)
            if spec is None:
                skipped += 1
            else:
                fixtures.append(spec)
    return fixtures, skipped


def discover_fixtures(
    validation_root: Path | None = None,
) -> list[FixtureSpec]:
    if validation_root is None:
        validation_root = Path(__file__).parent.parent.parent / "tests" / "scan" / "fixtures" / "validation"
    return _discover_fixtures_with_skips(validation_root)[0]


def _metrics_from_fixtures(
    fixtures: Sequence[FixtureSpec],
    advisory_db_path: str | Path | None = None,
) -> tuple[dict[str, RuleMetrics], list[tuple[str, str, tuple[str, ...]]]]:
    from .engine import create_default_engine

    engine = create_default_engine()
    metrics: dict[str, RuleMetrics] = {}
    fixture_results: list[tuple[str, str, tuple[str, ...]]] = []

    def _bump(rule_id: str, **kw: int) -> None:
        m = metrics.get(rule_id) or RuleMetrics(rule_id=rule_id)
        metrics[rule_id] = RuleMetrics(
            rule_id=rule_id,
            true_positives=m.true_positives + kw.get("tp", 0),
            false_positives=m.false_positives + kw.get("fp", 0),
            false_negatives=m.false_negatives + kw.get("fn", 0),
        )

    for spec in fixtures:
        try:
            result = engine.scan(spec.path, advisory_db_path=advisory_db_path)
        except Exception as exc:
            logger.exception("Fixture %s: scan raised", spec.name)
            fixture_results.append((spec.name, "ERROR", (str(exc),)))
            continue

        fired_ids = {f.rule_id for f in result.findings}
        findings = result.findings
        failures: list[str] = []
        if spec.label == "positive":
            missing = sorted(set(spec.expected_rule_ids) - fired_ids)
            failures = [f"missing:{m}" for m in missing]

            for rid in spec.expected_rule_ids:
                if rid in fired_ids:
                    _bump(rid, tp=1)
                else:
                    _bump(rid, fn=1)

            # Opt-in: strict positives reject any rule that fires but
            # isn't in expected_rule_ids. Default off so legacy fixtures
            # that rely on the asymmetric "extras allowed" semantics
            # (e.g. the multi-rule OBFS integration fixtures) keep
            # working.
            if spec.strict:
                extras = sorted(fired_ids - set(spec.expected_rule_ids))
                for x in extras:
                    failures.append(f"unexpected_rule:{x}")

            # Opt-in: per-finding gates. expected_findings entries must
            # match at least one finding; unexpected_findings entries
            # must match no finding. For expected_findings we dedupe by
            # fingerprint so the same finding doesn't satisfy multiple
            # assertions (one-to-one expected→actual mapping); for
            # unexpected_findings we deliberately do NOT dedupe, since
            # the semantics is "any finding matching = assertion fails"
            # and a single finding could legitimately violate several
            # unexpected assertions.
            seen: set = set()
            for ef in spec.expected_findings:
                if not any(_matches_finding(f, ef, seen=seen) for f in findings):
                    failures.append(f"expected_finding_absent:{ef.rule_id}")
            for uf in spec.unexpected_findings:
                if any(_matches_finding(f, uf) for f in findings):
                    failures.append(f"unexpected_finding_present:{uf.rule_id}")

            outcome = "PASS" if not failures else "FAIL"
            fixture_results.append((spec.name, outcome, tuple(failures)))
        else:  # negative
            unexpected = sorted(fired_ids)
            for rid in unexpected:
                _bump(rid, fp=1)
            if unexpected:
                failures.append(f"unexpected_rule:{','.join(unexpected)}")

            # Opt-in: forbidden_rule_ids asserts that a specific rule
            # MUST NOT fire on this clean project. Useful for per-rule
            # FP testing — "this clean npm project must not trigger
            # L2-TYPO-001 even though the name is rare."
            for rid in spec.forbidden_rule_ids:
                if rid in fired_ids:
                    failures.append(f"forbidden_rule_fired:{rid}")

            outcome = "PASS" if not failures else "FAIL"
            fixture_results.append((spec.name, outcome, tuple(failures)))

    return metrics, fixture_results


def run_validation(
    validation_root: Path | None = None,
    rules: Sequence[str] | None = None,
    output_path: Path | None = None,
    advisory_db_path: str | Path | None = None,
) -> ValidationReport:
    del rules  # Reserved for future rule-filtering; not used today.

    if validation_root is None:
        validation_root = Path(__file__).parent.parent.parent / "tests" / "scan" / "fixtures" / "validation"

    if advisory_db_path is None:
        auto_path = validation_root / "_advisories"
        if auto_path.is_dir():
            advisory_db_path = str(auto_path)

    fixtures, skipped = _discover_fixtures_with_skips(validation_root)
    metrics, fixture_results = _metrics_from_fixtures(fixtures, advisory_db_path=advisory_db_path)

    known = known_rule_ids()
    unknown_expectations = tuple(
        (spec.name, rid) for spec in fixtures for rid in spec.expected_rule_ids if rid not in known
    )
    for name, rid in unknown_expectations:
        logger.warning("Fixture %s expects unknown rule id %s — guaranteed recall loss", name, rid)

    report = ValidationReport(
        rule_metrics=tuple(metrics[r] for r in sorted(metrics)),
        total_fixtures=len(fixtures),
        total_positive=sum(1 for f in fixtures if f.label == "positive"),
        total_negative=sum(1 for f in fixtures if f.label == "negative"),
        fixture_results=tuple(fixture_results),
        unknown_rule_expectations=unknown_expectations,
        skipped_fixtures=skipped,
    )

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return report
