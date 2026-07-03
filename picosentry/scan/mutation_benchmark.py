"""Adversarial mutation benchmark for the PicoSentry scanner.

Copies each validation fixture into a temporary directory, mutates eligible
source files with deterministic transformations, runs the scanner, and reports
recall under mutation. The benchmark is the statistical complement to the
static fixture suite: it measures whether rules stay robust when attackers
apply cheap source-level evasions.
"""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .adversarial_mutations import (
    MUTATORS,
    apply_mutations,
    can_mutate_file,
)
from .engine import create_default_engine
from .validation import (
    FixtureSpec,
    RuleMetrics,
    discover_fixtures,
)

logger = logging.getLogger("picosentry.mutation_benchmark")


@dataclass(frozen=True)
class MutationBenchmarkConfig:
    """Configuration for a mutation benchmark run."""

    mutators: tuple[str, ...] = (
        "insert_comments",
        "pad_whitespace",
        "quote_swap",
        "rename_common_identifiers",
        "add_dead_code",
        "reorder_independent_lines",
    )
    seed: int = 42
    advisory_db_path: str | Path | None = None
    validation_root: Path | None = None
    include_negative_fixtures: bool = True

    def __post_init__(self) -> None:
        unknown = set(self.mutators) - set(MUTATORS)
        if unknown:
            raise ValueError(f"Unknown mutator(s): {sorted(unknown)}")


@dataclass(frozen=True)
class MutationFixtureResult:
    """Per-fixture outcome after mutation."""

    fixture_name: str
    label: str
    applied_mutations: tuple[str, ...]
    expected_rule_ids: tuple[str, ...]
    fired_rule_ids: frozenset[str]
    missing_rule_ids: tuple[str, ...]
    unexpected_rule_ids: tuple[str, ...]
    files_mutated: int

    @property
    def passed(self) -> bool:
        return not self.missing_rule_ids and not self.unexpected_rule_ids


@dataclass(frozen=True)
class MutationBenchmarkReport:
    """Aggregate report across all mutated fixtures."""

    config: MutationBenchmarkConfig
    fixture_results: tuple[MutationFixtureResult, ...]
    rule_metrics: tuple[RuleMetrics, ...] = field(default_factory=tuple)

    @property
    def total_positive(self) -> int:
        return sum(1 for r in self.fixture_results if r.label == "positive")

    @property
    def total_negative(self) -> int:
        return sum(1 for r in self.fixture_results if r.label == "negative")

    @property
    def total_files_mutated(self) -> int:
        return sum(r.files_mutated for r in self.fixture_results)

    @property
    def positive_pass_count(self) -> int:
        return sum(1 for r in self.fixture_results if r.label == "positive" and r.passed)

    @property
    def negative_pass_count(self) -> int:
        return sum(1 for r in self.fixture_results if r.label == "negative" and r.passed)

    @property
    def aggregate_recall(self) -> float:
        """TP / (TP + FN) across all rules with declared expectations."""
        tp = sum(m.true_positives for m in self.rule_metrics)
        fn = sum(m.false_negatives for m in self.rule_metrics)
        return tp / (tp + fn) if (tp + fn) > 0 else 0.0

    @property
    def aggregate_precision(self) -> float:
        """TP / (TP + FP) across all rules."""
        tp = sum(m.true_positives for m in self.rule_metrics)
        fp = sum(m.false_positives for m in self.rule_metrics)
        return tp / (tp + fp) if (tp + fp) > 0 else 0.0

    @property
    def passes_recall_floor(self, floor: float = 0.85) -> bool:
        return self.aggregate_recall >= floor

    def to_dict(self) -> dict[str, Any]:
        return {
            "config": {
                "mutators": list(self.config.mutators),
                "seed": self.config.seed,
                "include_negative_fixtures": self.config.include_negative_fixtures,
            },
            "summary": {
                "total_positive": self.total_positive,
                "total_negative": self.total_negative,
                "total_files_mutated": self.total_files_mutated,
                "positive_pass_count": self.positive_pass_count,
                "negative_pass_count": self.negative_pass_count,
                "aggregate_recall": round(self.aggregate_recall, 4),
                "aggregate_precision": round(self.aggregate_precision, 4),
            },
            "rule_metrics": [m.to_dict() for m in sorted(self.rule_metrics, key=lambda r: r.rule_id)],
            "fixture_results": [
                {
                    "fixture": r.fixture_name,
                    "label": r.label,
                    "passed": r.passed,
                    "applied_mutations": list(r.applied_mutations),
                    "expected_rule_ids": list(r.expected_rule_ids),
                    "fired_rule_ids": sorted(r.fired_rule_ids),
                    "missing_rule_ids": list(r.missing_rule_ids),
                    "unexpected_rule_ids": list(r.unexpected_rule_ids),
                    "files_mutated": r.files_mutated,
                }
                for r in self.fixture_results
            ],
        }

    def to_text(self) -> str:
        lines = [
            "PicoSentry adversarial mutation benchmark",
            "=" * 60,
            f"mutators: {', '.join(self.config.mutators)}",
            f"seed: {self.config.seed}",
            f"fixtures: {len(self.fixture_results)} (positive={self.total_positive}, negative={self.total_negative})",
            f"files mutated: {self.total_files_mutated}",
            f"aggregate recall: {self.aggregate_recall:.2%}",
            f"aggregate precision: {self.aggregate_precision:.2%}",
            "",
            f"positive pass: {self.positive_pass_count}/{self.total_positive}",
            f"negative pass: {self.negative_pass_count}/{self.total_negative}",
            "",
            "Per-rule metrics:",
        ]
        for m in sorted(self.rule_metrics, key=lambda r: r.rule_id):
            lines.append(
                f"  {m.rule_id:<28} TP={m.true_positives:>3} FP={m.false_positives:>3} "
                f"FN={m.false_negatives:>3} recall={m.recall:>7.2%}"
            )
        lines.append("")
        lines.append("Failing fixtures:")
        failures = [r for r in self.fixture_results if not r.passed]
        if not failures:
            lines.append("  none")
        else:
            for r in failures:
                details = []
                if r.missing_rule_ids:
                    details.append(f"missing={','.join(r.missing_rule_ids)}")
                if r.unexpected_rule_ids:
                    details.append(f"unexpected={','.join(r.unexpected_rule_ids)}")
                lines.append(f"  {r.fixture_name:<32} {'; '.join(details)}")
        return "\n".join(lines) + "\n"

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"


def _copy_and_mutate_fixture(
    spec: FixtureSpec,
    destination: Path,
    mutators: Sequence[str],
    seed: int,
) -> int:
    """Copy a fixture tree to *destination*, mutating eligible source files.

    Returns the number of files that were mutated.
    """
    files_mutated = 0
    for src in spec.path.rglob("*"):
        if not src.is_file():
            continue
        dst = destination / src.relative_to(spec.path)
        dst.parent.mkdir(parents=True, exist_ok=True)

        if not can_mutate_file(src):
            shutil.copy2(src, dst)
            continue

        try:
            text = src.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            shutil.copy2(src, dst)
            continue

        # Seed the per-file mutation with a combination of the global seed and
        # the file path so the same file mutates the same way across runs, but
        # different files mutate differently.
        file_seed = seed + sum(ord(c) for c in str(src))
        result = apply_mutations(text, mutators, seed=file_seed)
        if result.applied:
            dst.write_text(result.mutated, encoding="utf-8")
            files_mutated += 1
        else:
            shutil.copy2(src, dst)
    return files_mutated


def _score_fixture(
    spec: FixtureSpec,
    mutated_path: Path,
    engine: Any,
    advisory_db_path: str | Path | None,
) -> MutationFixtureResult:
    result = engine.scan(mutated_path, advisory_db_path=advisory_db_path)
    fired = frozenset(f.rule_id for f in result.findings)

    if spec.label == "positive":
        missing = tuple(sorted(set(spec.expected_rule_ids) - fired))
        # For positives we allow extra findings; only count declared misses.
        unexpected = ()
    else:
        missing = ()
        unexpected = tuple(sorted(fired))

    return MutationFixtureResult(
        fixture_name=spec.name,
        label=spec.label,
        applied_mutations=(),  # filled in by the caller
        expected_rule_ids=spec.expected_rule_ids,
        fired_rule_ids=fired,
        missing_rule_ids=missing,
        unexpected_rule_ids=unexpected,
        files_mutated=0,
    )


def run_mutation_benchmark(
    config: MutationBenchmarkConfig | None = None,
    output_path: Path | None = None,
) -> MutationBenchmarkReport:
    """Run the full adversarial mutation benchmark and return a report."""
    config = config or MutationBenchmarkConfig()
    fixtures = discover_fixtures(config.validation_root)

    # Auto-detect the bundled advisory database from the validation root so CI
    # and local runs use the same data without requiring callers to pass a path.
    advisory_db_path = config.advisory_db_path
    if advisory_db_path is None:
        validation_root = config.validation_root
        if validation_root is None:
            validation_root = Path(__file__).parent.parent.parent / "tests" / "scan" / "fixtures" / "validation"
        auto_path = validation_root / "_advisories"
        if auto_path.is_dir():
            advisory_db_path = str(auto_path)

    engine = create_default_engine(advisory_db_path=str(advisory_db_path) if advisory_db_path is not None else None)
    metrics: dict[str, RuleMetrics] = {}
    fixture_results: list[MutationFixtureResult] = []

    def _bump(rule_id: str, *, tp: int = 0, fp: int = 0, fn: int = 0) -> None:
        m = metrics.get(rule_id) or RuleMetrics(rule_id=rule_id)
        metrics[rule_id] = RuleMetrics(
            rule_id=rule_id,
            true_positives=m.true_positives + tp,
            false_positives=m.false_positives + fp,
            false_negatives=m.false_negatives + fn,
        )

    for spec in fixtures:
        if spec.label == "negative" and not config.include_negative_fixtures:
            continue

        with tempfile.TemporaryDirectory() as tmp:
            mutated_path = Path(tmp) / spec.name
            files_mutated = _copy_and_mutate_fixture(
                spec,
                mutated_path,
                config.mutators,
                config.seed,
            )

            outcome = _score_fixture(
                spec,
                mutated_path,
                engine,
                advisory_db_path,
            )
            outcome = MutationFixtureResult(
                fixture_name=outcome.fixture_name,
                label=outcome.label,
                applied_mutations=config.mutators,
                expected_rule_ids=outcome.expected_rule_ids,
                fired_rule_ids=outcome.fired_rule_ids,
                missing_rule_ids=outcome.missing_rule_ids,
                unexpected_rule_ids=outcome.unexpected_rule_ids,
                files_mutated=files_mutated,
            )
            fixture_results.append(outcome)

            if spec.label == "positive":
                for rid in spec.expected_rule_ids:
                    if rid in outcome.fired_rule_ids:
                        _bump(rid, tp=1)
                    else:
                        _bump(rid, fn=1)
            else:
                for rid in outcome.fired_rule_ids:
                    _bump(rid, fp=1)

    report = MutationBenchmarkReport(
        config=config,
        fixture_results=tuple(fixture_results),
        rule_metrics=tuple(metrics[r] for r in sorted(metrics)),
    )

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report.to_json(), encoding="utf-8")

    return report
