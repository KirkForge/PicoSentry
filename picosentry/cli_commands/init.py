"""`picosentry init` top-level command wiring."""

from __future__ import annotations

import argparse

from picosentry.cli_commands import register
from picosentry.cli_commands._maturity import emit_maturity_warning


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("init", help="Generate configuration template")
    parser.add_argument("target", type=str, nargs="?", default=".", help="Directory to create config in")
    parser.add_argument("--force", action="store_true", help="Overwrite existing config file")


def cmd(args: argparse.Namespace) -> int:
    emit_maturity_warning("init")
    from picosentry.scan.cli import main as scan_main

    scan_argv = ["init"]
    if getattr(args, "target", None):
        scan_argv.append(args.target)
    if getattr(args, "force", False):
        scan_argv.append("--force")
    return scan_main(argv=scan_argv)


register("init", add_arguments, cmd)
