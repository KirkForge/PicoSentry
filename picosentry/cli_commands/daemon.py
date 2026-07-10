"""`picosentry daemon` top-level command wiring."""

from __future__ import annotations

import argparse

from picosentry.cli_commands import register
from picosentry.cli_commands._maturity import emit_maturity_warning


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "daemon",
        help="Start PicoDome sandbox daemon (HTTP API + optional gRPC transport)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8443, help="HTTP bind port (default: 8443)")
    parser.add_argument("--background", action="store_true", help="Run in background")
    parser.add_argument("--transport", choices=["http", "grpc"], default="http", help="Transport protocol")
    parser.add_argument(
        "--grpc-port", type=int, default=50051, help="gRPC port (default: 50051, only used with --transport grpc)"
    )
    parser.add_argument(
        "--store-backend",
        choices=["jsonl", "sqlite"],
        default=None,
        help="Job store backend: jsonl (default) or sqlite",
    )
    parser.add_argument(
        "--metrics-port",
        type=int,
        default=None,
        help="Separate port for /metrics endpoint (default: same as API port)",
    )


def cmd(args: argparse.Namespace) -> int:
    emit_maturity_warning("daemon")
    from picosentry.sandbox.cli_commands import daemon as _daemon_mod

    return _daemon_mod.cmd(args)


register("daemon", add_arguments, cmd)
