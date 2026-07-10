"""`picosentry update` top-level command wiring."""

from __future__ import annotations

import argparse

from picosentry.cli_commands import register
from picosentry.cli_commands._maturity import emit_maturity_warning
from picosentry.scan.cli_commands import update as _update_mod


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    _update_mod.add_arguments(subparsers)


def cmd(args: argparse.Namespace) -> int:
    emit_maturity_warning("update")
    return _update_mod.cmd(args)


register("update", add_arguments, cmd)
