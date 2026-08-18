"""`picosentry scan` top-level command wiring.

The implementation lives in ``picosentry.scan.cli_commands.scan``; this module
registers it with the unified CLI and forwards arguments. It also exposes the
scan-side ``check`` and ``advisories`` commands by forwarding to
``picosentry.scan.cli`` (the ``python -m picosentry.scan`` entry point).
"""

from __future__ import annotations

import argparse

from picosentry.cli_commands import register
from picosentry.cli_commands._common import forward_flag
from picosentry.cli_commands._maturity import emit_maturity_warning
from picosentry.scan.cli_commands import check as _check_cmd
from picosentry.scan.cli_commands import scan as _scan_cmd


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    _scan_cmd.add_arguments(subparsers)


def cmd(args: argparse.Namespace) -> int:
    emit_maturity_warning("scan")
    return _scan_cmd.cmd(args)


register("scan", add_arguments, cmd)


# ─── `picosentry check` — forwards to `picosentry.scan check` ────────────


def add_check_arguments(subparsers: argparse._SubParsersAction) -> None:
    _check_cmd.add_arguments(subparsers)


def _cmd_check(args: argparse.Namespace) -> int:
    emit_maturity_warning("check")
    return _check_cmd.cmd(args)


register("check", add_check_arguments, _cmd_check)


# ─── `picosentry advisories` — forwards to `picosentry.scan advisories` ──


def add_advisories_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("advisories", help="Manage advisory database (fetch)")
    sub = parser.add_subparsers(dest="adv_action", help="Advisory actions")
    fetch = sub.add_parser("fetch", help="Download advisory database from central URL")
    fetch.add_argument("url", help="URL to advisory database (zip or JSON)")
    fetch.add_argument("--output", "-o", default=None, help="Output directory (default: $PICOADVISORY_DIR)")
    fetch.add_argument("--verify-crypto", action="store_true", help="Verify cryptographic signature on advisory bundle")
    fetch.add_argument(
        "--public-key", type=str, default="", help="Path to minisign public key (for minisign verification)"
    )
    fetch.add_argument("--offline", action="store_true", help="Use offline Sigstore verification")


def _cmd_advisories(args: argparse.Namespace) -> int:
    emit_maturity_warning("advisories")
    from picosentry.scan.cli import main as scan_main

    argv = ["advisories"]
    if getattr(args, "adv_action", None) == "fetch":
        argv.extend(["fetch", args.url])
        forward_flag(argv, args, "--output", "-o", default=None)
        forward_flag(argv, args, "--verify-crypto", boolean=True)
        forward_flag(argv, args, "--public-key", default="")
        forward_flag(argv, args, "--offline", boolean=True)
    return scan_main(argv)


register("advisories", add_advisories_arguments, _cmd_advisories)
