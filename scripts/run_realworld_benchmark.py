"""Run PicoSentry against the real-world train corpus and produce a benchmark report."""

from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REALWORLD_ROOT = REPO_ROOT / "datasets" / "realworld"
TRAIN_ROOT = REALWORLD_ROOT / "train"
METADATA_PATH = REALWORLD_ROOT / "METADATA.json"
OUTPUT_PATH = REALWORLD_ROOT / "BENCHMARK_RESULTS.json"


@dataclass(frozen=True)
class RuleMetrics:
    rule_id: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        d = self.true_positives + self.false_positives
        return self.true_positives / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.true_positives + self.false_negatives
        return self.true_positives / d if d else 0.0

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
        }


def discover_fixtures(root: Path) -> list[dict]:
    fixtures = []
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
                {
                    "path": fixture_dir,
                    "label": label,
                    "expected_rule_ids": tuple(data.get("expected_rule_ids", ())),
                    "category": data.get("category", "unknown"),
                    "ecosystem": data.get("ecosystem", eco_dir.name),
                    "description": data.get("description", ""),
                    "package_name": data.get("package_name", fixture_dir.name),
                }
            )
    return fixtures


def run_benchmark() -> dict:
    from picosentry.scan.engine import create_default_engine

    engine = create_default_engine()
    fixtures = discover_fixtures(TRAIN_ROOT)
    print(f"Discovered {len(fixtures)} fixtures")

    rule_metrics: dict[str, RuleMetrics] = {}
    eco_stats: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "total": 0})
    cat_stats: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "total": 0})
    errors = 0
    negatives_with_findings = 0
    total_negatives = 0

    t0 = time.time()
    for i, spec in enumerate(fixtures, 1):
        if i % 100 == 0:
            print(f"  ...scanned {i}/{len(fixtures)}", flush=True)
        try:
            result = engine.scan(spec["path"])
        except Exception as exc:
            errors += 1
            print(f"  ERROR: {spec['path'].name}: {exc}")
            continue

        fired_ids = {f.rule_id for f in result.findings}
        eco = spec["ecosystem"]
        cat = spec["category"]

        if spec["label"] == "positive":
            for rid in spec["expected_rule_ids"]:
                m = rule_metrics.get(rid) or RuleMetrics(rule_id=rid)
                if rid in fired_ids:
                    rule_metrics[rid] = replace(m, true_positives=m.true_positives + 1)
                    eco_stats[eco]["tp"] += 1
                    cat_stats[cat]["tp"] += 1
                else:
                    rule_metrics[rid] = replace(m, false_negatives=m.false_negatives + 1)
                    eco_stats[eco]["fn"] += 1
                    cat_stats[cat]["fn"] += 1
            eco_stats[eco]["total"] += 1
            cat_stats[cat]["total"] += 1
        else:
            total_negatives += 1
            if fired_ids:
                negatives_with_findings += 1
                for rid in fired_ids:
                    m = rule_metrics.get(rid) or RuleMetrics(rule_id=rid)
                    rule_metrics[rid] = replace(m, false_positives=m.false_positives + 1)
                    eco_stats[eco]["fp"] += 1
                    cat_stats[cat]["fp"] += 1
            eco_stats[eco]["total"] += 1
            cat_stats[cat]["total"] += 1

    elapsed = time.time() - t0

    def _pr(tp: int, fp: int, fn: int) -> tuple[float, float]:
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        return prec, rec

    rule_rows = []
    for m in sorted(rule_metrics.values(), key=lambda r: r.rule_id):
        rule_rows.append(m.to_dict())

    eco_rows = []
    for eco in sorted(eco_stats):
        s = eco_stats[eco]
        prec, rec = _pr(s["tp"], s["fp"], s["fn"])
        eco_rows.append(
            {
                "ecosystem": eco,
                "total": s["total"],
                "tp": s["tp"],
                "fp": s["fp"],
                "fn": s["fn"],
                "precision": round(prec, 4),
                "recall": round(rec, 4),
            }
        )

    cat_rows = []
    for cat in sorted(cat_stats):
        s = cat_stats[cat]
        prec, rec = _pr(s["tp"], s["fp"], s["fn"])
        cat_rows.append(
            {
                "category": cat,
                "total": s["total"],
                "tp": s["tp"],
                "fp": s["fp"],
                "fn": s["fn"],
                "precision": round(prec, 4),
                "recall": round(rec, 4),
            }
        )

    total_tp = sum(m.true_positives for m in rule_metrics.values())
    total_fp = sum(m.false_positives for m in rule_metrics.values())
    total_fn = sum(m.false_negatives for m in rule_metrics.values())
    overall_prec, overall_rec = _pr(total_tp, total_fp, total_fn)

    mean_rule_prec = sum(m.precision for m in rule_metrics.values()) / len(rule_metrics) if rule_metrics else 0.0
    mean_rule_rec = sum(m.recall for m in rule_metrics.values()) / len(rule_metrics) if rule_metrics else 0.0

    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "corpus": "train",
        "total_fixtures": len(fixtures),
        "errors": errors,
        "elapsed_seconds": round(elapsed, 1),
        "overall": {
            "true_positives": total_tp,
            "false_positives": total_fp,
            "false_negatives": total_fn,
            "precision": round(overall_prec, 4),
            "recall": round(overall_rec, 4),
        },
        "mean_per_rule": {
            "precision": round(mean_rule_prec, 4),
            "recall": round(mean_rule_rec, 4),
        },
        "negatives": {
            "total": total_negatives,
            "with_findings": negatives_with_findings,
            "false_positive_rate": round(negatives_with_findings / total_negatives, 4) if total_negatives else 0.0,
        },
        "per_ecosystem": eco_rows,
        "per_category": cat_rows,
        "per_rule": rule_rows,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\nResults written to {OUTPUT_PATH}")

    print("\n=== PicoSentry Real-World Benchmark (train set) ===\n")
    print(f"Fixtures: {len(fixtures)} | Errors: {errors} | Time: {elapsed:.1f}s\n")
    print(f"Overall precision: {overall_prec:.2%} | Overall recall: {overall_rec:.2%}")
    print(f"Mean per-rule precision: {mean_rule_prec:.2%} | Mean per-rule recall: {mean_rule_rec:.2%}")
    print(f"Negative fixtures with findings: {negatives_with_findings}/{total_negatives}\n")

    print("Per-ecosystem:")
    for row in eco_rows:
        print(f"  {row['ecosystem']:<10} P={row['precision']:.2%}  R={row['recall']:.2%}  n={row['total']}")

    print("\nPer-category:")
    for row in cat_rows:
        print(f"  {row['category']:<20} P={row['precision']:.2%}  R={row['recall']:.2%}  n={row['total']}")

    print(f"\nPer-rule ({len(rule_rows)} rules triggered):")
    print(f"  {'rule_id':<28} {'TP':>4} {'FP':>4} {'FN':>4} {'precision':>10} {'recall':>8}")
    for row in rule_rows:
        print(
            f"  {row['rule_id']:<28} {row['true_positives']:>4} {row['false_positives']:>4} "
            f"{row['false_negatives']:>4} {row['precision']:>10.2%} {row['recall']:>8.2%}"
        )

    return report


if __name__ == "__main__":
    if not TRAIN_ROOT.is_dir():
        print(f"Train corpus not found at {TRAIN_ROOT}", file=sys.stderr)
        sys.exit(1)
    run_benchmark()
