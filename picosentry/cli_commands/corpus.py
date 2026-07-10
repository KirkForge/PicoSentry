"""`picosentry corpus` top-level command wiring."""

from __future__ import annotations

import argparse

from picosentry.cli_commands import register
from picosentry.cli_commands._maturity import emit_maturity_warning
from picosentry.scan.cli_commands import corpus as _corpus_mod


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    _corpus_mod.add_arguments(subparsers)


def cmd(args: argparse.Namespace) -> int:
    emit_maturity_warning("corpus")
    return _corpus_mod.cmd(args)


register("corpus", add_arguments, cmd)
