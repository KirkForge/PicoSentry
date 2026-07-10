"""`picosentry rules` top-level command wiring."""

from __future__ import annotations

import argparse

from picosentry.cli_commands import register
from picosentry.cli_commands._maturity import emit_maturity_warning


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("rules", help="List available scanner rules")
    parser.add_argument("--json", "-j", action="store_true", dest="json_output", help="Output as JSON")


def cmd(args: argparse.Namespace) -> int:
    emit_maturity_warning("rules")
    from picosentry.scan.cli import main as scan_main

    scan_argv = ["rules"]
    if getattr(args, "json_output", False):
        scan_argv.append("--json")
    return scan_main(argv=scan_argv)


register("rules", add_arguments, cmd)
