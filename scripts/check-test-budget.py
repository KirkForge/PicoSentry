#!/usr/bin/env python3
"""Check a pytest junit.xml against slow-test budgets.

Prints a markdown top-N slowest-tests table and exits 1 when any single test
exceeds its per-test budget or the summed suite time exceeds --total-budget
(--warn downgrades breaches to a report). Stdlib only, so it runs on a bare
CI runner via python3. Wired as: PR = warn, push = enforce, nightly = warn
(enforce once a baseline exists — #62/#63).

Usage:
  python3 scripts/check-test-budget.py JUNIT.xml [--budget S] [--total-budget S]
                                        [--top N] [--warn] [--out FILE.md]
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET

DEFAULT_BUDGET = 60.0  # matches the fast-profile pytest timeout
TOP_N = 20

# Per-suite budget overrides in seconds: substring match against the junit
# classname (pytest emits e.g. "tests.sandbox.test_exec"). "sandbox" also
# matches "tests/sandbox/..." style classnames.
SUITE_BUDGETS = {
    "sandbox": 120.0,  # sandbox tests spawn real subprocesses
}


def budget_for(classname: str, default: float) -> float:
    for fragment, seconds in SUITE_BUDGETS.items():
        if fragment in classname:
            return seconds
    return default


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Slow-test budget check against a pytest junit.xml.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("junit", help="path to pytest --junitxml output")
    parser.add_argument(
        "--budget", type=float, default=DEFAULT_BUDGET, help="default per-test budget in seconds (default: %(default)s)"
    )
    parser.add_argument(
        "--total-budget", type=float, default=None, help="max summed test time in seconds (default: no total budget)"
    )
    parser.add_argument("--top", type=int, default=TOP_N, help="table size (default: %(default)s)")
    parser.add_argument("--warn", action="store_true", help="report budget breaches but exit 0")
    parser.add_argument("--out", default=None, help="also write the markdown table to this file")
    args = parser.parse_args()

    try:
        root = ET.parse(args.junit).getroot()
    except (OSError, ET.ParseError) as exc:
        print(f"ERROR: cannot parse {args.junit}: {exc}", file=sys.stderr)
        return 2

    cases = []
    for tc in root.iter("testcase"):
        seconds = float(tc.get("time") or 0)
        classname = tc.get("classname") or ""
        name = tc.get("name") or tc.get("file") or "?"
        cases.append((seconds, classname, name))
    if not cases:
        print(f"ERROR: no <testcase> elements in {args.junit}", file=sys.stderr)
        return 2

    total = sum(c[0] for c in cases)
    breaches = [c for c in cases if c[0] > budget_for(c[1], args.budget)]
    total_breach = args.total_budget is not None and total > args.total_budget

    lines = [
        "## Slowest tests",
        "",
        f"- tests: {len(cases)}  |  summed time: {total:.1f}s"
        f"  |  budget: {args.budget:g}s/test (total: "
        f"{f'{args.total_budget:g}s' if args.total_budget is not None else 'none'})"
        f"  |  breaches: {len(breaches)}",
        "",
        "| # | time (s) | test |",
        "|---:|---:|---|",
    ]
    for i, (seconds, classname, name) in enumerate(sorted(cases, reverse=True)[: args.top], 1):
        marker = " **OVER BUDGET**" if seconds > budget_for(classname, args.budget) else ""
        lines.append(f"| {i} | {seconds:.2f} | {classname}.{name}{marker} |")
    report = "\n".join(lines)
    print(report)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(report + "\n")

    if breaches or total_breach:
        for seconds, classname, name in breaches:
            print(
                f"BUDGET: {classname}.{name} took {seconds:.1f}s (budget {budget_for(classname, args.budget):g}s)",
                file=sys.stderr,
            )
        if total_breach:
            print(f"BUDGET: suite total {total:.1f}s exceeds --total-budget {args.total_budget:g}s", file=sys.stderr)
        if args.warn:
            print("warn mode: breaches reported, not enforced", file=sys.stderr)
            return 0
        return 1
    print("budget check: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
