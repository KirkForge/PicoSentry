"""`ioc` subcommand — manage custom IoC indicators (register/list/remove).

Extracted in v2.1.0 (refactor) from the monolithic ``picosentry/scan/cli.py``.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

NAME = "ioc"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Manage custom IoC indicators (register/list/remove)")
    sub = parser.add_subparsers(dest="ioc_action", help="IoC actions")

    register = sub.add_parser("register", help="Register a new custom IoC from a JSON file")
    register.add_argument("path", type=str, help="Path to IoC .json file")
    register.add_argument("--force", "-f", action="store_true", help="Overwrite existing IoC with same ID")

    sub.add_parser("list", help="List all user-registered custom IoCs")

    remove = sub.add_parser("remove", help="Remove a custom IoC by ID")
    remove.add_argument("id", type=str, help="IoC ID to remove")


def cmd(args: argparse.Namespace) -> int:
    """Manage custom IoC indicators."""
    from picosentry.scan.ioc_registry import list_custom_iocs, register_ioc, remove_ioc

    if not args.ioc_action:
        print("Usage: picosentry ioc {register|list|remove}")
        return 1

    if args.ioc_action == "list":
        iocs = list_custom_iocs()
        if not iocs:
            print("No custom IoCs registered.")
            return 0
        print(f"Custom IoCs ({len(iocs)}):")
        for ioc in iocs:
            print(f"  {ioc.id}  {ioc.package_name:30s}  [{ioc.severity}]  {ioc.name}")
        return 0

    elif args.ioc_action == "register":
        path = Path(args.path)
        if not path.exists():
            print(f"Error: IoC file not found: {path}", file=sys.stderr)
            return 2
        if path.suffix.lower() != ".json":
            print(f"Error: IoC file must be JSON, got: {path.suffix}", file=sys.stderr)
            return 2
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            record = register_ioc(data, allow_overwrite=args.force)
            print(f"Registered IoC: {record.id} ({record.name})")
            print(f"  Package: {record.package_name}")
            print(f"  Type:    {record.ioc_type}")
            print(f"  Severity: {record.severity}")
        except (json.JSONDecodeError, FileExistsError, ValueError) as e:
            print(f"Error registering IoC: {e}", file=sys.stderr)
            return 1
        return 0

    elif args.ioc_action == "remove":
        try:
            found = remove_ioc(args.id)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        if found:
            print(f"Removed IoC: {args.id}")
        else:
            print(f"IoC not found: {args.id}")
            return 1
        return 0

    return 0


# Back-compat alias
_cmd_ioc = cmd

__all__ = ["NAME", "_cmd_ioc", "add_arguments", "cmd"]
