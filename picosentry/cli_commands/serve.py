"""`picosentry serve` top-level command wiring.

The implementation lives in ``picosentry.serve.api.server``; this module
registers it with the unified CLI and forwards environment variables.
"""

from __future__ import annotations

import argparse
import os

from picosentry.cli_commands import register
from picosentry.cli_commands._common import import_or_warn
from picosentry.cli_commands._maturity import emit_maturity_warning


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    serve_parser = subparsers.add_parser("serve", help="Start API server, dashboard, and orchestration")
    serve_parser.add_argument("--host", type=str, default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8765)
    serve_parser.add_argument("--reload", action="store_true", help="Enable hot reload")
    serve_parser.add_argument("--workers", type=int, default=1)
    serve_parser.add_argument(
        "--plugin-dir",
        action="append",
        default=[],
        dest="plugin_dirs",
        metavar="PATH",
        help="Additional plugin directory to scan (repeatable). The bundled "
        "picosentry/serve/plugins/ is always scanned; this adds extras. "
        "Takes precedence over the PICOSHOGUN_PLUGIN_DIR env var.",
    )
    serve_parser.add_argument(
        "--require-signed-plugins",
        action="store_true",
        help="Refuse to load plugins that are not signed by a trusted Ed25519 key",
    )
    serve_parser.add_argument(
        "--trusted-public-keys",
        type=str,
        default=None,
        metavar="HEX_KEYS",
        help="Comma-separated Ed25519 public keys (hex) trusted for plugin signatures",
    )


def cmd(args: argparse.Namespace) -> int:
    emit_maturity_warning("serve")

    if args.host:
        os.environ["PICOSHOGUN_API_HOST"] = args.host
    if args.port:
        os.environ["PICOSHOGUN_API_PORT"] = str(args.port)
    if args.reload:
        os.environ["PICOSHOGUN_API_RELOAD"] = "true"
    if args.workers:
        os.environ["PICOSHOGUN_API_WORKERS"] = str(args.workers)
    if getattr(args, "require_signed_plugins", False):
        os.environ["PICOSHOGUN_REQUIRE_SIGNED_PLUGINS"] = "1"
    trusted_keys = getattr(args, "trusted_public_keys", None)
    if trusted_keys:
        os.environ["PICOSHOGUN_TRUSTED_PUBLIC_KEYS"] = trusted_keys

    plugin_dirs = list(getattr(args, "plugin_dirs", []) or [])
    if plugin_dirs:
        existing = os.environ.get("PICOSHOGUN_PLUGIN_DIR", "").strip()
        merged = [p for p in (existing.split(",") if existing else []) if p]
        merged.extend(plugin_dirs)
        os.environ["PICOSHOGUN_PLUGIN_DIR"] = ",".join(merged)

    serve_main = import_or_warn(
        lambda: __import__("picosentry.serve.api.server", fromlist=["main"]).main,
        "serve",
        "the 'serve' subcommand (API server + dashboard)",
    )

    if plugin_dirs:
        try:
            from picosentry.serve.services.plugin_manager import plugin_manager

            plugin_manager.reload(plugin_dirs)
        except ImportError:
            pass  # serve extra not installed; nothing to do

    return serve_main()


register("serve", add_arguments, cmd)
