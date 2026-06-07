from __future__ import annotations

import argparse
import json

from picosentry.sandbox.l4.engine import create_default_engine

NAME = "rules"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="List available L4 detector rules")
    parser.add_argument("--json", action="store_true", help="Output as JSON")


def cmd(args: argparse.Namespace) -> int:
    engine = create_default_engine()
    rules = engine.list_rules()
    if args.json:
        print(json.dumps({"rules": rules}))
    else:
        for r in rules:
            print(r)
    return 0


__all__ = ["NAME", "add_arguments", "cmd"]
