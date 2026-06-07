"""PicoSentry — CLI entry point (v2.1.0 refactor: orchestrator + back-compat shim).

The original ``picosentry/scan/cli.py`` was 1940 lines. v2.1.0 splits each
subcommand into its own module under ``picosentry/scan/cli_commands/``:

- ``scan``       — the core scan pipeline
- ``check``      — CI-optimized health check
- ``diff``       — compare two scan JSON files
- ``init``       — generate a .picosentry.yml config template
- ``update``     — download top-N npm packages (network)
- ``workspace``  — scan a monorepo/workspace
- ``corpus``     — manage custom IoC corpus packs
- ``ioc``        — manage custom IoC indicators
- ``policy``     — manage enterprise policy bundles
- ``advisories`` — manage the advisory database
- ``daemon``     — start the HTTP daemon
- ``cache``      — manage the scan result cache
- ``metrics``    — print current metrics
- ``benchmark``  — show detection quality metrics
- ``rules``      — list available detector rules
- ``version``    — show PicoSentry version

This file is now a thin orchestrator:

1. Builds the top-level argparse parser and the subparsers.
2. Calls each subcommand module's ``add_arguments`` to register its
   subparser.
3. Dispatches the parsed args to the matching module's ``cmd``.

For back-compat, this file re-exports the symbols the test suite and
``picosentry/cli.py`` import directly:

- ``main(argv)`` (the public entry point)
- ``ScanTimeout``, ``ScanError`` (exception types)
- The private ``_cmd_*`` handlers and helpers that the v2.0.x test
  suite imported directly (e.g. ``_cmd_update``, ``_cmd_check``,
  ``_cmd_corpus``, ``_cmd_diff``, ``_cmd_init``, ``_cmd_ioc``,
  ``_cmd_policy``, ``_cmd_advisories``, ``_cmd_workspace``,
  ``_run_scan``, ``_format_quiet``, ``_format_summary``,
  ``_verify_determinism``, ``_handle_validate``, ``_scan_worker``).

The shim is on the deprecation path for v2.2.0: new code should import
from ``picosentry.scan.cli_commands.<name>`` directly.
"""
from __future__ import annotations

import argparse
import logging
import sys

from picosentry.scan import __version__
from picosentry.scan.cli_commands import (
    benchmark,
    cache,
    check,
    corpus,
    daemon,
    diff,
    init,
    ioc,
    metrics,
    advisories,
    policy,
    rules,
    scan,
    update,
    version,
    workspace,
)
from picosentry.scan.logging import configure_logging

logger = logging.getLogger(__name__)


# ── Subcommand registry (drives argparse + dispatch) ──────────────────────

_REGISTRY = (
    scan,
    check,
    diff,
    init,
    update,
    workspace,
    corpus,
    ioc,
    policy,
    advisories,
    daemon,
    cache,
    metrics,
    benchmark,
    rules,
    version,
)


# ── Public entry point ────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    """Build the parser, dispatch to the matching subcommand module.

    Returns the integer exit code of the subcommand handler (or 0 for
    no-op cases like ``--version`` / no command / ``--help``).
    """
    parser = argparse.ArgumentParser(
        prog="picosentry",
        description="PicoSentry — deterministic supply-chain scanner for npm/pnpm",
    )
    parser.add_argument(
        "--log-format",
        choices=["text", "json"],
        default=None,
        help="Log output format: text (default) or json for SIEM integration",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="store_true",
        help="Show PicoSentry version and exit",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    for mod in _REGISTRY:
        mod.add_arguments(subparsers)

    args = parser.parse_args(argv)

    # Configure structured logging for SIEM integration
    if hasattr(args, "log_format") and args.log_format == "json":
        configure_logging(log_format="json")

    # `--version` short-circuit (handled at the parser level, not a subcommand)
    if args.version:
        return version.cmd(args)

    if args.command is None:
        parser.print_help()
        return 0

    for mod in _REGISTRY:
        if args.command == mod.NAME:
            return mod.cmd(args)

    return 0


# ── Back-compat re-exports ────────────────────────────────────────────────
# The v2.0.x test suite imports these symbols directly from
# ``picosentry.scan.cli``. The re-exports keep the test surface stable.

ScanTimeout = scan.ScanTimeout
ScanError = scan.ScanError

# Aliases for the historic `_cmd_<name>` naming convention.
_cmd_check = check.cmd
_cmd_diff = diff.cmd
_cmd_init = init.cmd
_cmd_update = update.cmd
_cmd_workspace = workspace.cmd
_cmd_corpus = corpus.cmd
_cmd_ioc = ioc.cmd
_cmd_policy = policy.cmd
_cmd_advisories = advisories.cmd

# Subcommand-internal helpers (also called by tests directly).
_run_scan = scan._run_scan
_scan_worker = scan._scan_worker
_format_summary = scan._format_summary
_format_quiet = scan._format_quiet
_verify_determinism = scan._verify_determinism
_handle_validate = scan._handle_validate


# ── `if __name__ == "__main__"` for `python -m picosentry.scan` ──────────

if __name__ == "__main__":
    sys.exit(main())
