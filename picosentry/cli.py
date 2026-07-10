"""Unified ``picosentry`` entry point.

Subcommands are registered by the modules under ``picosentry.cli_commands``.
Each module exports ``add_arguments`` and ``cmd`` and calls
``register(name, ...)`` at import time.  This file only builds the root parser
and dispatches to the registered command.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

# Import command modules to trigger their ``register`` calls.
# ruff: noqa: F401
from picosentry.cli_commands import (
    admission,
    corpus,
    daemon,
    diff,
    health,
    init,
    rules,
    sandbox,
    scan,
    serve,
    update,
    version,
    watch,
)
from picosentry.cli_commands import add_all_arguments, registered_commands, run
from picosentry.cli_commands._common import (
    extra_for_missing_module as _extra_for_missing_module,
    import_or_warn as _import_or_warn,
)
from picosentry.cli_commands._maturity import (
    _COMMAND_MATURITY,
    emit_maturity_warning as _emit_maturity_warning,
)


def _get_unified_version() -> str:
    try:
        from picosentry import __version__

        return __version__
    except ImportError:
        return "0.0.0"


def _handle_health() -> int:
    return run("health", argparse.Namespace())


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="picosentry",
        description="Unified Pico Security Series — scan, sandbox, watch, orchestrate.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="store_true", help="Show version and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")
    add_all_arguments(subparsers)

    args = parser.parse_args(argv)

    if args.version:
        return run("version", args)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    if args.command is None:
        parser.print_help()
        return 0

    # Legacy behavior: scan's --quiet/--summary demote cache HMAC warnings.
    if args.command == "scan" and (getattr(args, "quiet", False) or getattr(args, "summary", False)):
        os.environ.setdefault("PICOSENTRY_QUIET", "1")

    return run(args.command, args)


if __name__ == "__main__":
    sys.exit(main())
