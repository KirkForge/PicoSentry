"""`version` subcommand — print PicoDome version and exit.

Extracted in v2.1.0 (refactor) from ``picosentry/sandbox/cli.py``.
"""
from __future__ import annotations

import argparse

from picosentry.sandbox import __version__

NAME = "version"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    subparsers.add_parser(NAME, help="Print version and exit")


def cmd(args: argparse.Namespace) -> int:
    """Print version and exit."""
    print(f"picodome {__version__}")
    return 0


__all__ = ["NAME", "add_arguments", "cmd"]
