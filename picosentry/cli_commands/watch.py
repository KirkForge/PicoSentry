"""`picosentry watch` top-level command wiring.

The implementation lives in ``picosentry.watch.cli``; this module registers
it with the unified CLI and forwards arguments.
"""

from __future__ import annotations

import argparse
import os

from picosentry.cli_commands import register
from picosentry.cli_commands._common import import_or_warn
from picosentry.cli_commands._maturity import emit_maturity_warning


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    watch_parser = subparsers.add_parser("watch", help="LLM prompt injection detection and output validation")
    watch_sub = watch_parser.add_subparsers(dest="watch_command")

    scan_prompt_p = watch_sub.add_parser("scan-prompt", help="Scan a prompt for injection attempts")
    scan_prompt_p.add_argument("--text", "-t", type=str, default=None, help="Prompt text to scan")
    scan_prompt_p.add_argument("--file", "-f", type=str, default=None, help="File containing prompt text")

    validate_p = watch_sub.add_parser("validate-output", help="Validate LLM output against a schema")
    validate_p.add_argument("--schema", "-s", type=str, required=True, help="Schema file path")
    validate_p.add_argument("--output", "-o", type=str, required=True, help="Output file to validate")

    watch_sub.add_parser("rules", help="List available watch rules")
    watch_sub.add_parser("health", help="Check watch health")

    serve_watch_p = watch_sub.add_parser("serve", help="Start PicoWatch HTTP daemon")
    serve_watch_p.add_argument("--host", type=str, default="127.0.0.1")
    serve_watch_p.add_argument("--port", "-p", type=int, default=8766)


def cmd(args: argparse.Namespace) -> int:
    emit_maturity_warning("watch")

    wants_http = getattr(args, "watch_command", None) == "serve"
    watch_main = import_or_warn(
        lambda: __import__("picosentry.watch.cli", fromlist=["main"]).main,
        "watch-server",
        "the 'watch serve' subcommand (HTTP daemon)" if wants_http else "the 'watch' subcommand",
    )

    watch_argv: list[str] = []
    watch_command = getattr(args, "watch_command", None)
    if watch_command:
        watch_argv.append(watch_command)
        if watch_command == "scan-prompt":
            if args.text:
                watch_argv.extend(["--text", args.text])
            if args.file:
                watch_argv.extend(["--file", args.file])
        elif watch_command == "validate-output":
            watch_argv.extend(["--schema", args.schema, "--output", args.output])
        elif watch_command == "serve":
            watch_argv.extend(["--host", args.host, "--port", str(args.port)])
    else:
        watch_argv.append("--help")

    return watch_main(watch_argv or None)


register("watch", add_arguments, cmd)
