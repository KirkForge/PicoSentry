"""`health` subcommand — run PicoDome health checks.

Extracted in v2.1.0 (refactor) from ``picosentry/sandbox/cli.py``.
"""
from __future__ import annotations

import argparse
import json

NAME = "health"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Run health checks")
    parser.add_argument("--format", "-f", choices=["json", "table"], default="table", help="Output format")


def cmd(args: argparse.Namespace) -> int:
    """Run health checks."""
    from picosentry.sandbox.health import check_health

    checks = check_health()
    all_healthy = all(c.healthy for c in checks)

    if args.format == "json":
        data = {
            "healthy": all_healthy,
            "checks": [c.to_dict() for c in checks],
        }
        print(json.dumps(data, sort_keys=True, indent=2))
    else:
        icon = "✓" if all_healthy else "✗"
        print(f"\n{icon} PicoDome Health: {'HEALTHY' if all_healthy else 'UNHEALTHY'}\n")
        for c in checks:
            icon = "✓" if c.healthy else "✗"
            print(f"  {icon} {c.component}: {c.detail}")

    return 0 if all_healthy else 1


__all__ = ["NAME", "add_arguments", "cmd"]
