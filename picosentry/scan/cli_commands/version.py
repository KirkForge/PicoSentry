"""`version` subcommand — show PicoSentry version + corpus + rule counts.

Extracted in v2.1.0 (refactor) from the monolithic ``picosentry/scan/cli.py``.
The handler was inlined in the original ``main()``; here it lives in its
own module for consistency with the per-subcommand pattern.
"""
from __future__ import annotations

import argparse

from picosentry.scan import __version__
from picosentry.scan.engine import create_default_engine

NAME = "version"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    subparsers.add_parser(NAME, help="Show PicoSentry version")


def cmd(args: argparse.Namespace) -> int:
    """Print version, corpus version, and rule count."""
    from picosentry.scan.rules import RULE_INFO

    engine = create_default_engine()
    print(f"picosentry v{__version__}")
    print(f"corpus: {engine._corpus_version}")
    print(f"rules:  {len(RULE_INFO)} ({len(engine.list_rules())} detector functions)")
    return 0


__all__ = ["NAME", "add_arguments", "cmd"]
