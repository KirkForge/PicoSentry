from __future__ import annotations

import argparse
import logging
import sys

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


def main(argv: list[str] | None = None) -> int:
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


    if hasattr(args, "log_format") and args.log_format == "json":
        configure_logging(log_format="json")


    if args.version:
        return version.cmd(args)

    if args.command is None:
        parser.print_help()
        return 0

    for mod in _REGISTRY:
        if args.command == mod.NAME:
            return mod.cmd(args)

    return 0


ScanTimeout = scan.ScanTimeout
ScanError = scan.ScanError


_cmd_check = check.cmd
_cmd_diff = diff.cmd
_cmd_init = init.cmd
_cmd_update = update.cmd
_cmd_workspace = workspace.cmd
_cmd_corpus = corpus.cmd
_cmd_ioc = ioc.cmd
_cmd_policy = policy.cmd
_cmd_advisories = advisories.cmd


_run_scan = scan._run_scan
_scan_worker = scan._scan_worker
_format_summary = scan._format_summary
_format_quiet = scan._format_quiet
_verify_determinism = scan._verify_determinism
_handle_validate = scan._handle_validate


if __name__ == "__main__":
    sys.exit(main())
