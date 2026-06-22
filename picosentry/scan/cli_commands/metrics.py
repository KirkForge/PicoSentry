from __future__ import annotations

import argparse

NAME = "metrics"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Print current metrics as JSON")
    parser.add_argument(
        "--format", choices=["json", "prometheus"], default="json", help="Output format (default: json)"
    )


def cmd(args: argparse.Namespace) -> int:
    from picosentry.scan.metrics import get_metrics

    snapshot = get_metrics().snapshot()
    if args.format == "prometheus":
        print(snapshot.to_prometheus())
    else:
        print(snapshot.to_json())
    return 0


__all__ = ["NAME", "add_arguments", "cmd"]
