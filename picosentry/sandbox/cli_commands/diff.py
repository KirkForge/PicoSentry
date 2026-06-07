"""`diff` subcommand — compare two result JSON files.

Extracted in v2.1.0 (refactor) from ``picosentry/sandbox/cli.py``.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from picosentry.sandbox.guards import diff_results

NAME = "diff"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Compare two result JSON files")
    parser.add_argument("file_a", type=Path, help="First result JSON file")
    parser.add_argument("file_b", type=Path, help="Second result JSON file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed diff")


def cmd(args: argparse.Namespace) -> int:
    """Compare two result JSON files."""
    exit_code, message = diff_results(args.file_a, args.file_b, verbose=args.verbose)
    print(message)
    return exit_code


__all__ = ["NAME", "add_arguments", "cmd"]
