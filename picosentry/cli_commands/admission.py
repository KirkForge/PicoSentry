"""`picosentry admission` top-level command wiring."""

from __future__ import annotations

import argparse

from picosentry.cli_commands import register
from picosentry.cli_commands._maturity import emit_maturity_warning


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "admission",
        help="Start PicoDome K8s admission webhook server (TLS required)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8443, help="Bind port (default: 8443)")
    parser.add_argument("--cert-file", required=True, help="Path to TLS certificate file (PEM)")
    parser.add_argument("--key-file", required=True, help="Path to TLS private key file (PEM)")
    parser.add_argument("--background", action="store_true", help="Run in background")
    parser.add_argument("--scan-enabled", action="store_true", default=None, help="Enable container image scanning")
    parser.add_argument(
        "--scan-min-severity",
        choices=["info", "low", "medium", "high", "critical"],
        default="high",
        help="Minimum severity for image-scan blocking (default: high)",
    )
    parser.add_argument(
        "--daemon-url",
        default=None,
        help="PicoDome daemon URL for image scanning (default: http://127.0.0.1:8443)",
    )


def cmd(args: argparse.Namespace) -> int:
    emit_maturity_warning("admission")
    from picosentry.sandbox.cli_commands import admission as _admission_mod

    return _admission_mod.cmd(args)


register("admission", add_arguments, cmd)
