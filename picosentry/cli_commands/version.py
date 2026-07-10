"""`picosentry version` top-level command wiring."""

from __future__ import annotations

import argparse

from picosentry.cli_commands import register


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    subparsers.add_parser("version", help="Show version and exit")


def cmd(_args: argparse.Namespace) -> int:
    try:
        from picosentry.scan import __version__ as scan_version
    except ImportError:
        scan_version = "N/A"
    try:
        from picosentry.sandbox import __version__ as sandbox_version
    except ImportError:
        sandbox_version = "N/A"
    try:
        from picosentry.watch import __version__ as watch_version
    except ImportError:
        watch_version = "N/A"
    try:
        from picosentry.serve.config.version import __version__ as serve_version
    except ImportError:
        serve_version = "N/A"
    try:
        from picosentry import __version__ as unified_version
    except ImportError:
        unified_version = "0.0.0"

    print(f"PicoSentry (unified) v{unified_version}")
    print(f"  scan:    v{scan_version}")
    print(f"  sandbox: v{sandbox_version}")
    print(f"  watch:   v{watch_version}")
    print(f"  serve:   v{serve_version}")
    return 0


register("version", add_arguments, cmd)
