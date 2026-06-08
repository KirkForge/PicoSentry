#!/usr/bin/env python3
"""Render the per-rule table in docs/BENCHMARKS.md from REPORT.json.

Walks tests/scan/fixtures/validation/ to count per-rule n_pos / n_neg
(declared coverage in each fixture.json), then splices a fresh table
into docs/BENCHMARKS.md between the BEGIN/END sentinels.

Run from the repo root:
    python scripts/render_benchmarks.py

Exit code 0 on success, non-zero if the sentinels are missing or the
inputs don't exist. Designed to be followed by `git diff --exit-code
docs/BENCHMARKS.md` in CI to catch doc drift.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / "tests/scan/fixtures/validation/REPORT.json"
BENCH = ROOT / "docs/BENCHMARKS.md"
FX = ROOT / "tests/scan/fixtures/validation"

BEGIN = "<!-- BEGIN: rule-table -->\n"
END = "<!-- END: rule-table -->\n"


def main() -> int:
    if not REPORT.exists() or not BENCH.exists():
        print("REPORT.json or BENCHMARKS.md missing; cannot render.", file=sys.stderr)
        return 1

    # Walk fixtures to count per-rule declared coverage.
    coverage: dict[str, dict[str, int]] = {}
    for label, key, counter in (
        ("positive", "expected_rule_ids", "n_pos"),
        ("negative", "forbidden_rule_ids", "n_neg"),
    ):
        for fjson in (FX / label).glob("*/fixture.json"):
            for rid in json.loads(fjson.read_text()).get(key, []):
                coverage.setdefault(rid, {"n_pos": 0, "n_neg": 0})[counter] += 1

    report = json.loads(REPORT.read_text())
    rms = report["rule_metrics"]

    # Build per-rule rows.
    rows: list[str] = []
    for m in sorted(rms, key=lambda m: m["rule_id"]):
        c = coverage.get(m["rule_id"], {"n_pos": 0, "n_neg": 0})
        rows.append(
            f"| {m['rule_id']:<23} | {c['n_pos']:>4} | {c['n_neg']:>4} | "
            f"{m['true_positives']:>2} | {m['false_positives']:>2} | "
            f"{m['false_negatives']:>2} | {m['precision']:>7.2%} | "
            f"{m['recall']:>7.2%} |"
        )

    # Aggregate row.
    tot = {
        "np": sum(c.get("n_pos", 0) for c in coverage.values()),
        "nn": sum(c.get("n_neg", 0) for c in coverage.values()),
        "tp": sum(m["true_positives"] for m in rms),
        "fp": sum(m["false_positives"] for m in rms),
        "fn": sum(m["false_negatives"] for m in rms),
    }
    mean_p = report["mean_precision"]
    mean_r = report["mean_recall"]
    rows.append(
        f"| **{'Aggregate':<23}** | **{tot['np']:>4}** | **{tot['nn']:>4}** | "
        f"**{tot['tp']:>2}** | **{tot['fp']:>2}** | **{tot['fn']:>2}** | "
        f"**{mean_p:>7.2%}** | **{mean_r:>7.2%}** |"
    )

    table = (
        "| rule_id                 | n_pos | n_neg | TP | FP | FN | "
        "precision | recall |\n"
        "|-------------------------|------:|------:|---:|---:|---:|"
        "----------:|-------:|\n"
        + "\n".join(rows)
    )

    text = BENCH.read_text()
    if BEGIN not in text or END not in text:
        print(
            "Sentinels not found in BENCHMARKS.md; cannot splice. "
            "Add <!-- BEGIN: rule-table --> and <!-- END: rule-table --> "
            "around the per-rule table.",
            file=sys.stderr,
        )
        return 2
    pre, _, rest = text.partition(BEGIN)
    _, _, post = rest.partition(END)
    BENCH.write_text(pre + BEGIN + table + "\n" + END + post)
    print(f"Rendered {len(rms)} rules into {BENCH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
