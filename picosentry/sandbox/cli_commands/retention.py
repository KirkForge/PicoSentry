from __future__ import annotations

import argparse
import json
from pathlib import Path

NAME = "retention"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Manage data retention")
    parser.add_argument("action", choices=["cleanup", "stats", "export"], help="Retention action")
    parser.add_argument("--output", type=Path, help="Output file for export")


def cmd(args: argparse.Namespace) -> int:
    from picosentry.sandbox.retention import get_retention_manager

    rm = get_retention_manager()

    if args.action == "cleanup":
        stats = rm.run_cleanup()
        print(f"Cleanup: removed {stats['files_removed']} files, freed {stats['bytes_freed']} bytes")
        if stats["errors"]:
            for err in stats["errors"]:
                print(f"  Error: {err}")
        return 0
    if args.action == "stats":
        stats = rm.get_storage_stats()
        print(json.dumps(stats, sort_keys=True, indent=2))
        return 0
    if args.action == "export":
        output = args.output or Path("picodome-export.json")
        rm.export_data(output)
        print(f"Exported to {output}")
        return 0
    return 1


__all__ = ["NAME", "add_arguments", "cmd"]
