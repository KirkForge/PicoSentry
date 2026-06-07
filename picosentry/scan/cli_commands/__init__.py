"""Subcommand modules for ``picosentry.scan.cli``.

Extracted in v2.1.0 (refactor) from the monolithic ``picosentry/scan/cli.py``
(1940 lines). Each module exposes two functions:

- ``add_arguments(subparsers)`` — register the subparser
- ``cmd(args) -> int`` — handle the parsed args

The module also declares ``NAME = "..."`` for the dispatch table in the
slim ``cli.py`` orchestrator.

This split keeps each subcommand's argparse wiring, handler, and
per-subcommand imports in one focused module. The public entry point
``picosentry.scan.cli.main(argv)`` and the private symbols the test
suite imports (``_cmd_update``, ``_scan_worker``, ``_format_quiet``,
etc.) are kept available via the back-compat shim at
``picosentry/scan/cli.py``.
"""
from __future__ import annotations

# Public re-exports for the orchestrator's dispatch table. Internal
# subcommand modules are not re-exported; import them directly when
# needed (e.g. ``from picosentry.scan.cli_commands import scan``).
