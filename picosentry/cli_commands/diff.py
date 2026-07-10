"""`picosentry diff` top-level command wiring."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from picosentry.cli_commands import register
from picosentry.cli_commands._maturity import emit_maturity_warning


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("diff", help="Compare two scan result JSONs")
    parser.add_argument("path_a", type=str, help="First scan result")
    parser.add_argument("path_b", type=str, help="Second scan result")
    parser.add_argument("--verbose", action="store_true", help="Show detailed diff")


def cmd(args: argparse.Namespace) -> int:
    emit_maturity_warning("diff")
    from picosentry.scan.guards import diff_scans

    result = diff_scans(Path(args.path_a), Path(args.path_b), verbose=args.verbose)
    print(result[1])
    return result[0]


register("diff", add_arguments, cmd)
