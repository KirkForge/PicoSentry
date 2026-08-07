"""`picosentry diff` top-level command wiring."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from picosentry.cli_commands import register
from picosentry.cli_commands._maturity import emit_maturity_warning


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("diff", help="Compare two scan result JSONs or package versions")
    parser.add_argument("path_a", type=str, nargs="?", help="First scan result JSON (legacy mode)")
    parser.add_argument("path_b", type=str, nargs="?", help="Second scan result JSON (legacy mode)")
    parser.add_argument("--verbose", action="store_true", help="Show detailed diff")
    parser.add_argument("--old", type=str, help="Old package manifest path (package.json)")
    parser.add_argument("--new", type=str, help="New package manifest path (package.json)")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output as JSON")


def cmd(args: argparse.Namespace) -> int:
    emit_maturity_warning("diff")

    if args.old and args.new:
        from picosentry.scan.version_diff import VersionDiff, format_delta

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

    if args.path_a and args.path_b:
        from picosentry.scan.guards import diff_scans

        result = diff_scans(Path(args.path_a), Path(args.path_b), verbose=args.verbose)
        print(result[1])
        return result[0]

    print("picosentry diff: provide two scan JSONs or --old/--new manifest paths", file=sys.stderr)
    return 2


register("diff", add_arguments, cmd)
