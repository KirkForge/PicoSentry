from __future__ import annotations

import argparse
from pathlib import Path

from picosentry.scan.guards import diff_scans

NAME = "diff"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Compare two scan JSON files for determinism verification")
    parser.add_argument("scan_a", type=str, help="First scan JSON file (baseline)")
    parser.add_argument("scan_b", type=str, help="Second scan JSON file (comparison)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed diff of findings")


def cmd(args: argparse.Namespace) -> int:
    path_a = Path(args.scan_a)
    path_b = Path(args.scan_b)
    verbose = getattr(args, "verbose", False)

    exit_code, output = diff_scans(path_a, path_b, verbose=verbose)
    print(output)
    return exit_code


__all__ = ["NAME", "add_arguments", "cmd"]
