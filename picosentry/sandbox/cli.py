"""PicoDome CLI — orchestrator (v2.1.0 refactor).

The original ``picosentry/sandbox/cli.py`` was 1461 lines. v2.1.0 splits
each subcommand into its own module under ``picosentry/sandbox/cli_commands/``:

- ``sandbox``          — Run a command under L3 sandbox policy
- ``analyze``          — Run L4 behavioral analysis on L3 output
- ``pipeline``         — Run full L3+L4 pipeline on a command
- ``rules``            — List available L4 detector rules
- ``diff``             — Compare two result JSON files
- ``init``             — Initialize PicoDome configuration
- ``daemon``           — Start PicoDome daemon (HTTP or gRPC)
- ``scan-grpc``        — Scan via gRPC client
- ``health``           — Run health checks
- ``audit``            — Query the audit log
- ``retention``        — Manage data retention
- ``policy-versions``  — Manage versioned policies
- ``notary``           — Audit transparency notary (Rekor/Sigstore)
- ``cluster``          — Manage daemon cluster mode
- ``sign-policy``      — Sign or verify a policy file
- ``version``          — Print PicoDome version

This file is now a thin orchestrator:

1. Builds the top-level argparse parser.
2. Calls each subcommand module's ``add_arguments`` to register its
   subparser.
3. Parses ``argv`` and dispatches to the matching module's ``cmd``.

The shim is on the deprecation path for v2.2.0: new code should import
from ``picosentry.sandbox.cli_commands.<name>`` directly.
"""
from __future__ import annotations

import argparse
import sys

from picosentry.sandbox import __version__
from picosentry.sandbox.cli_commands import (
    analyze,
    audit,
    cluster,
    daemon,
    diff,
    health,
    init,
    notary,
    pipeline,
    policy_versions,
    retention,
    rules,
    sandbox,
    scan_grpc,
    sign_policy,
    version,
)

# ── Subcommand registry (drives argparse + dispatch) ──────────────────────

_REGISTRY = (
    sandbox,
    analyze,
    pipeline,
    rules,
    diff,
    init,
    cluster,
    daemon,
    scan_grpc,
    health,
    audit,
    retention,
    policy_versions,
    sign_policy,
    notary,
    version,
)


# ── Public entry point ────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    """Build the parser, dispatch to the matching subcommand module.

    Returns the integer exit code of the subcommand handler (or 0 for
    no-op cases like ``--help``).
    """
    parser = argparse.ArgumentParser(
        prog="picodome",
        description="PicoDome — deterministic runtime sandbox and behavioral analysis",
    )
    parser.add_argument("--version", action="version", version=f"picodome {__version__}")

    sub = parser.add_subparsers(dest="subcommand", help="sub-commands")

    for mod in _REGISTRY:
        mod.add_arguments(sub)

    args = parser.parse_args(argv)

    if args.subcommand is None:
        parser.print_help()
        return 0

    for mod in _REGISTRY:
        if args.subcommand == mod.NAME:
            return mod.cmd(args)

    parser.print_help()
    return 1


# ── `if __name__ == "__main__"` for `python -m picosentry.sandbox` ────────

if __name__ == "__main__":
    sys.exit(main())
