#!/usr/bin/env python3
"""Run the adversarial mutation benchmark from the command line.

This is the local entry point for P5 #11 corpus statistical validation. It
mutates eligible source files in the validation fixtures, scans them, and
prints a recall/precision summary. Exit code is non-zero if the aggregate
recall floor (default 85%) or precision floor (default 95%) is not met.

Usage:
    python scripts/mutation_benchmark.py
    python scripts/mutation_benchmark.py --mutators insert_comments pad_whitespace
    python scripts/mutation_benchmark.py --seed 123 --output report.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Adversarial mutation benchmark for PicoSentry scanner rules",
    )
    parser.add_argument(
        "--mutators",
        nargs="+",
        default=None,
        help="Mutator names to apply (default: full suite)",
    )
    parser.add_argument("--seed", type=int, default=42, help="Deterministic seed")
    parser.add_argument(
        "--recall-floor",
        type=float,
        default=0.85,
        help="Minimum aggregate recall (default: 0.85)",
    )
    parser.add_argument(
        "--precision-floor",
        type=float,
        default=0.95,
        help="Minimum aggregate precision (default: 0.95)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="JSON report output path",
    )
    parser.add_argument(
        "--skip-negatives",
        action="store_true",
        help="Skip negative fixtures (precision measurement)",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    from picosentry.scan.adversarial_mutations import MUTATORS
    from picosentry.scan.mutation_benchmark import (
        MutationBenchmarkConfig,
        run_mutation_benchmark,
    )

    if args.mutators:
        unknown = set(args.mutators) - set(MUTATORS)
        if unknown:
            print(f"Unknown mutator(s): {sorted(unknown)}", file=sys.stderr)
            print(f"Available: {sorted(MUTATORS)}", file=sys.stderr)
            return 2
        mutators = tuple(args.mutators)
    else:
        mutators = MutationBenchmarkConfig().mutators

    config = MutationBenchmarkConfig(
        mutators=mutators,
        seed=args.seed,
        include_negative_fixtures=not args.skip_negatives,
    )

    report = run_mutation_benchmark(config, output_path=args.output)
    print(report.to_text())

    if args.output:
        print(f"Wrote JSON report to {args.output}")

    failed = []
    if report.aggregate_recall < args.recall_floor:
        failed.append(f"recall {report.aggregate_recall:.2%} < floor {args.recall_floor:.2%}")
    if report.aggregate_precision < args.precision_floor:
        failed.append(f"precision {report.aggregate_precision:.2%} < floor {args.precision_floor:.2%}")

    if failed:
        print("FAILED:", "; ".join(failed), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
