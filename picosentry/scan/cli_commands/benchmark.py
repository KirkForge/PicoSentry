"""`benchmark` subcommand — show detection quality metrics and known limitations.

Extracted in v2.1.0 (refactor) from the monolithic ``picosentry/scan/cli.py``.
"""
from __future__ import annotations

import argparse

NAME = "benchmark"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Show detection quality metrics and known limitations")
    parser.add_argument("--rule", type=str, default="", help="Show metrics for a specific rule ID (default: all rules)")
    parser.add_argument("--family", type=str, default="", help="Filter by rule family (e.g. typosquat, obfuscation)")
    parser.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")
    parser.add_argument("--limitations", action="store_true", help="Show known limitations per detector")
    parser.add_argument("--noisy", action="store_true", help="Show only noisy rules (high FP rate)")


def cmd(args: argparse.Namespace) -> int:
    """Show detection quality metrics."""
    from picosentry.scan.detection_quality import DetectionBenchmark

    bench = DetectionBenchmark()
    rule_id = getattr(args, "rule", "")
    family = getattr(args, "family", "")
    json_output = getattr(args, "json_output", False)
    show_limitations = getattr(args, "limitations", False)
    noisy_only = getattr(args, "noisy", False)

    if json_output:
        print(bench.to_json())
        return 0

    if noisy_only:
        noisy = bench.get_noisy_rules()
        if not noisy:
            print("No noisy rules found.")
            return 0
        print(f"Noisy rules ({len(noisy)}):\n")
        for m in noisy:
            print(
                f"  {m.rule_id:<18} {m.rule_family:<15} P={m.precision:.2f}  R={m.recall:.2f}  FP_rate={m.fp_rate:.2f}"
            )
            print(f"    Suppressed by default: {m.suppressed_by_default}")
        return 0

    if show_limitations:
        limitations = bench.get_limitations(rule_id=rule_id)
        if not limitations:
            print("No known limitations found.")
            return 0
        print(f"Known limitations ({len(limitations)}):\n")
        for lim in limitations:
            print(f"  {lim.rule_id:<18} [{lim.category}] {lim.description}")
            if lim.workaround:
                print(f"    Workaround: {lim.workaround}")
        return 0

    if rule_id:
        metrics = bench.get_metrics(rule_id)
        if not metrics:
            print(f"No metrics found for rule {rule_id}")
            return 1
        for _, m in metrics.items():
            print(f"Rule:       {m.rule_id}")
            print(f"Family:     {m.rule_family}")
            print(f"Precision:  {m.precision:.4f}")
            print(f"Recall:     {m.recall:.4f}")
            print(f"F1:         {m.f1:.4f}")
            print(f"TP/FP/FN:   {m.true_positives}/{m.false_positives}/{m.false_negatives}")
            print(f"Noisy:      {m.noisy}")
            print(f"Suppressed: {m.suppressed_by_default}")
        return 0

    if family:
        families = bench.get_metrics_by_family()
        fam_rules = families.get(family, [])
        if not fam_rules:
            print(f"No rules found for family '{family}'")
            return 1
        print(f"\nDetection quality - {family} family ({len(fam_rules)} rules):\n")
        print(f"{'Rule ID':<18} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Noisy':>6}")
        print("-" * 58)
        for m in fam_rules:
            print(
                f"{m.rule_id:<18} {m.precision:>10.4f} {m.recall:>10.4f} {m.f1:>10.4f} {'Yes' if m.noisy else 'No':>6}"
            )
        return 0

    # Overall benchmark
    quality = bench.overall_quality()
    print("\nPicoSentry Detection Quality Benchmark")
    print("=" * 45)
    print(f"  Version:       {quality['version']}")
    print(f"  Rules:         {quality['rules']}")
    print(f"  Overall P:     {quality['overall_precision']:.4f}")
    print(f"  Overall R:     {quality['overall_recall']:.4f}")
    print(f"  Overall F1:    {quality['overall_f1']:.4f}")
    print(f"  Noisy rules:   {quality['noisy_rules']}")
    print(f"  Limitations:   {quality['known_limitations']}")
    print()
    print("Per-rule metrics:")
    print(f"  {'Rule ID':<18} {'Family':<15} {'P':>6} {'R':>6} {'F1':>6} {'Noisy':>6}")
    print("  " + "-" * 62)
    metrics = bench.get_metrics()
    for _rid, m in sorted(metrics.items()):
        noisy_flag = "Yes" if m.noisy else ""
        print(
            f"  {m.rule_id:<18} {m.rule_family:<15} {m.precision:>6.2f} {m.recall:>6.2f} {m.f1:>6.2f} {noisy_flag:>6}"
        )
    return 0


__all__ = ["NAME", "add_arguments", "cmd"]
