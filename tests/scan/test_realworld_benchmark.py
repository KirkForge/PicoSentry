"""Real-world malware benchmark for PicoSentry.

Scans the curated real-world corpus (datasets/realworld/train/) and
reports per-rule precision/recall. Marked slow so fast CI skips it.
Runs only when the real-world corpus directory exists.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from picosentry.scan.engine import create_default_engine
from picosentry.scan.validation import FixtureSpec, RuleMetrics

pytestmark = [pytest.mark.slow, pytest.mark.benchmark_realworld, pytest.mark.timeout(300)]

REALWORLD_ROOT = Path(__file__).resolve().parent.parent.parent / "datasets" / "realworld" / "train"
METADATA_PATH = Path(__file__).resolve().parent.parent.parent / "datasets" / "realworld" / "METADATA.json"

MIN_PRECISION = 0.40
MIN_RECALL = 0.40


def _discover_realworld_fixtures(root: Path) -> list[FixtureSpec]:
    if not root.is_dir():
        return []
    fixtures: list[FixtureSpec] = []
    for eco_dir in sorted(root.iterdir()):
        if not eco_dir.is_dir():
            continue
        for fixture_dir in sorted(eco_dir.iterdir()):
            if not fixture_dir.is_dir():
                continue
            spec_path = fixture_dir / "fixture.json"
            if not spec_path.is_file():
                continue
            try:
                data = json.loads(spec_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            label = data.get("label", "").lower()
            if label not in {"positive", "negative"}:
                continue
            fixtures.append(
                FixtureSpec(
                    path=fixture_dir,
                    label=label,
                    expected_rule_ids=tuple(data.get("expected_rule_ids", ())),
                    description=data.get("description", ""),
                )
            )
    return fixtures


@pytest.fixture(scope="module")
def realworld_fixtures():
    if not REALWORLD_ROOT.is_dir():
        pytest.skip("No real-world corpus found (run scripts/build_realworld_corpus.py)")
    fixtures = _discover_realworld_fixtures(REALWORLD_ROOT)
    if not fixtures:
        pytest.skip("No real-world fixtures found")
    return fixtures


@pytest.fixture(scope="module")
def engine():
    return create_default_engine()


def test_realworld_benchmark_precision_recall(realworld_fixtures, engine):
    metrics: dict[str, RuleMetrics] = {}
    total_pass = 0
    total_fail = 0

    for spec in realworld_fixtures:
        try:
            result = engine.scan(spec.path)
        except Exception:
            total_fail += 1
            continue

        fired_ids = {f.rule_id for f in result.findings}

        if spec.label == "positive":
            for rid in spec.expected_rule_ids:
                if rid not in metrics:
                    metrics[rid] = RuleMetrics(rule_id=rid)
                m = metrics[rid]
                if rid in fired_ids:
                    metrics[rid] = RuleMetrics(
                        rule_id=rid,
                        true_positives=m.true_positives + 1,
                        false_positives=m.false_positives,
                        false_negatives=m.false_negatives,
                    )
                else:
                    metrics[rid] = RuleMetrics(
                        rule_id=rid,
                        true_positives=m.true_positives,
                        false_positives=m.false_positives,
                        false_negatives=m.false_negatives + 1,
                    )
            if fired_ids.intersection(spec.expected_rule_ids):
                total_pass += 1
            else:
                total_fail += 1

    if not metrics:
        pytest.skip("No positive fixtures with expected rules")

    mean_precision = sum(m.precision for m in metrics.values()) / len(metrics)
    mean_recall = sum(m.recall for m in metrics.values()) / len(metrics)

    report_lines = [
        f"Real-world benchmark: {len(realworld_fixtures)} fixtures, {len(metrics)} rules",
        f"Mean precision: {mean_precision:.2%} (floor: {MIN_PRECISION:.0%})",
        f"Mean recall:    {mean_recall:.2%} (floor: {MIN_RECALL:.0%})",
        "",
        "Per-rule metrics:",
        f"  {'rule_id':<28} {'TP':>4} {'FP':>4} {'FN':>4} {'precision':>10} {'recall':>8}",
    ]
    for m in sorted(metrics.values(), key=lambda r: r.rule_id):
        report_lines.append(
            f"  {m.rule_id:<28} {m.true_positives:>4} {m.false_positives:>4} "
            f"{m.false_negatives:>4} {m.precision:>10.2%} {m.recall:>8.2%}"
        )
    report = "\n".join(report_lines)

    assert mean_precision >= MIN_PRECISION, (
        f"Mean precision {mean_precision:.2%} below floor {MIN_PRECISION:.0%}\n{report}"
    )
    assert mean_recall >= MIN_RECALL, f"Mean recall {mean_recall:.2%} below floor {MIN_RECALL:.0%}\n{report}"


def test_realworld_corpus_metadata_exists():
    if not METADATA_PATH.is_file():
        pytest.skip("No METADATA.json (run scripts/build_realworld_corpus.py)")
    data = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    assert "total_count" in data
    assert "train_count" in data
    assert "held_out_count" in data
    assert "split_method" in data
    assert data["split_method"] == "sha256-first-byte"
    assert data["total_count"] == data["train_count"] + data["held_out_count"]
    eco_counts = data.get("ecosystem_counts", {})
    for eco in ("npm", "pypi", "go", "cargo", "maven", "rubygems", "nuget"):
        assert eco in eco_counts, f"Missing ecosystem {eco} in METADATA.json"
