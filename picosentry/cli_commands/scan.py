"""`picosentry scan` top-level command wiring.

The implementation lives in ``picosentry.scan.cli_commands.scan``; this module
registers it with the unified CLI.
"""

from __future__ import annotations

import argparse

from picosentry.cli_commands import register
from picosentry.cli_commands._maturity import emit_maturity_warning
from picosentry.scan.cli_commands import scan as _scan_cmd


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    _scan_cmd.add_arguments(subparsers)


def cmd(args: argparse.Namespace) -> int:
    emit_maturity_warning("scan")
    return _scan_cmd.cmd(args)


register("scan", add_arguments, cmd)
