from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from picosentry.scan.guards import diff_scans
from picosentry.scan.version_diff import VersionDiff, format_delta

NAME = "diff"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Compare two scan JSON files or package versions")
    parser.add_argument("scan_a", type=str, nargs="?", help="First scan JSON file (baseline)")
    parser.add_argument("scan_b", type=str, nargs="?", help="Second scan JSON file (comparison)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed diff of findings")
    parser.add_argument("--old", type=str, help="Old package manifest path")
    parser.add_argument("--new", type=str, help="New package manifest path")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output as JSON")


def cmd(args: argparse.Namespace) -> int:
    if args.old and args.new:
        differ = VersionDiff()
        old_path = Path(args.old)
        new_path = Path(args.new)

        if not old_path.is_file():
            print(f"picosentry diff: old manifest not found: {old_path}", file=sys.stderr)
            return 2
        if not new_path.is_file():
            print(f"picosentry diff: new manifest not found: {new_path}", file=sys.stderr)
            return 2

        delta = differ.diff_files(old_path, new_path)

        if args.json_output:
            print(json.dumps(delta.to_dict(), indent=2, sort_keys=True))
        else:
            print(format_delta(delta))
        return 0 if delta.verdict.value in ("CLEAN", "LOW_RISK") else 1

    if args.scan_a and args.scan_b:
        path_a = Path(args.scan_a)
        path_b = Path(args.scan_b)
        verbose = getattr(args, "verbose", False)

        exit_code, output = diff_scans(path_a, path_b, verbose=verbose)
        print(output)
        return exit_code

    print("picosentry diff: provide two scan JSONs or --old/--new manifest paths", file=sys.stderr)
    return 2


__all__ = ["NAME", "add_arguments", "cmd"]
