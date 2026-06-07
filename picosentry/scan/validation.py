
from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("picosentry.validation")


@dataclass(frozen=True)
class FixtureSpec:

    path: Path
    label: str  # "positive" | "negative"
    expected_rule_ids: tuple[str, ...] = ()
    description: str = ""

    @property
    def name(self) -> str:
        return self.path.name


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


@dataclass(frozen=True)
class ValidationReport:

    rule_metrics: tuple[RuleMetrics, ...] = ()
    total_fixtures: int = 0
    total_positive: int = 0
    total_negative: int = 0
    fixture_results: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
    """(fixture_name, "PASS" | "FAIL", (missing_rule_ids_or_unexpected_rule_ids,))"""

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
        }

    def to_text(self) -> str:
        lines: list[str] = []
        lines.append("PicoSentry validation report")
        lines.append("=" * 60)
        lines.append(
            f"fixtures: {self.total_fixtures} "
            f"(positive: {self.total_positive}, negative: {self.total_negative})"
        )
        lines.append(f"mean precision: {self.mean_precision:.2%}")
        lines.append(f"mean recall:    {self.mean_recall:.2%}")
        lines.append("")
        lines.append("Per-rule metrics:")
        lines.append(
            f"  {'rule_id':<28} {'TP':>4} {'FP':>4} {'FN':>4} {'precision':>10} {'recall':>8}"
        )
        for m in sorted(self.rule_metrics, key=lambda r: r.rule_id):
            lines.append(
                f"  {m.rule_id:<28} {m.true_positives:>4} {m.false_positives:>4} "
                f"{m.false_negatives:>4} {m.precision:>10.2%} {m.recall:>8.2%}"
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
    label = data.get("label", "").lower()
    if label not in {"positive", "negative"}:
        logger.warning("Fixture %s: label must be 'positive' or 'negative'", path)
        return None
    return FixtureSpec(
        path=path,
        label=label,
        expected_rule_ids=tuple(data.get("expected_rule_ids", ())),
        description=data.get("description", ""),
    )


def discover_fixtures(
    validation_root: Path | None = None,
) -> list[FixtureSpec]:
    if validation_root is None:
        validation_root = (
            Path(__file__).parent.parent.parent / "tests" / "scan" / "fixtures" / "validation"
        )
    if not validation_root.is_dir():
        return []
    fixtures: list[FixtureSpec] = []
    for sub in ("positive", "negative"):
        sub_root = validation_root / sub
        if not sub_root.is_dir():
            continue
        for entry in sorted(sub_root.iterdir()):
            if not entry.is_dir():
                continue
            spec = _load_fixture(entry)
            if spec is not None:
                fixtures.append(spec)
    return fixtures


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
            logger.error("Fixture %s: scan raised %s", spec.name, exc)
            fixture_results.append((spec.name, "ERROR", (str(exc),)))
            continue

        fired_ids = {f.rule_id for f in result.findings}
        if spec.label == "positive":

            missing = sorted(set(spec.expected_rule_ids) - fired_ids)


            for rid in spec.expected_rule_ids:
                if rid in fired_ids:
                    _bump(rid, tp=1)
                else:
                    _bump(rid, fn=1)
            outcome = "PASS" if not missing else "FAIL"
            fixture_results.append((spec.name, outcome, tuple(missing)))
        else:  # negative

            unexpected = sorted(fired_ids)
            for rid in unexpected:
                _bump(rid, fp=1)
            outcome = "PASS" if not unexpected else "FAIL"
            fixture_results.append((spec.name, outcome, tuple(unexpected)))

    return metrics, fixture_results


def run_validation(
    validation_root: Path | None = None,
    rules: Sequence[str] | None = None,
    output_path: Path | None = None,
    advisory_db_path: str | Path | None = None,
) -> ValidationReport:
    del rules  # Reserved for future rule-filtering; not used today.

    if validation_root is None:
        validation_root = (
            Path(__file__).parent.parent.parent / "tests" / "scan" / "fixtures" / "validation"
        )

    if advisory_db_path is None:
        auto_path = validation_root / "_advisories"
        if auto_path.is_dir():
            advisory_db_path = str(auto_path)

    fixtures = discover_fixtures(validation_root)
    metrics, fixture_results = _metrics_from_fixtures(fixtures, advisory_db_path=advisory_db_path)

    report = ValidationReport(
        rule_metrics=tuple(metrics[r] for r in sorted(metrics)),
        total_fixtures=len(fixtures),
        total_positive=sum(1 for f in fixtures if f.label == "positive"),
        total_negative=sum(1 for f in fixtures if f.label == "negative"),
        fixture_results=tuple(fixture_results),
    )

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return report
