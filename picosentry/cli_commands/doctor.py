"""`picosentry doctor` top-level command wiring."""

from __future__ import annotations

import argparse

from picosentry._core.doctor import verify
from picosentry.cli_commands import register


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("doctor", help="Run self-verification and optional repair checks")
    parser.add_argument("--repair", action="store_true", help="Auto-repair fixable issues before verification")
    parser.add_argument("--json", dest="output_json", action="store_true", help="Output report as JSON")


def cmd(args: argparse.Namespace) -> int:
    report = verify(repair=args.repair)

    if args.output_json:
        print(report.to_json())
        return 0

    icon = {"pass": "\u2713", "fail": "\u2717", "warn": "\u2605"}
    for check in report.checks:
        sym = icon.get(check.status, "?")
        line = f"  {sym} {check.status:4} {check.name:35} {check.detail}"
        if check.repaired:
            line += f"  [REPAIRED: {check.repair_detail}]"
        print(line)

    print("=" * 70)
    print(f"  {report.summary()}  ({report.elapsed:.1f}s)")

    if not report.all_passed():
        return 1
    return 0


register("doctor", add_arguments, cmd)
