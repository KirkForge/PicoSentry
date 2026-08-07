from __future__ import annotations

import argparse

from picosentry.cli_commands import register
from picosentry.cli_commands._maturity import emit_maturity_warning


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("firewall", help="Start registry proxy firewall")
    parser.add_argument("--port", type=int, default=3132, help="Listen port (default: 3132)")
    parser.add_argument("--upstream-npm", default="https://registry.npmjs.org", help="Upstream npm registry URL")
    parser.add_argument("--upstream-pypi", default="https://pypi.org", help="Upstream PyPI registry URL")
    parser.add_argument(
        "--block-severities",
        default="CRITICAL,HIGH",
        help="Comma-separated severities that trigger BLOCK (default: CRITICAL,HIGH)",
    )
    parser.add_argument(
        "--quarantine-severities",
        default="MEDIUM",
        help="Comma-separated severities that trigger QUARANTINE (default: MEDIUM)",
    )
    parser.add_argument("--cache-ttl", type=int, default=3600, help="Cache TTL in seconds (default: 3600)")
    parser.add_argument("--scan-timeout", type=int, default=30, help="Scan timeout in seconds (default: 30)")
    parser.add_argument("--no-log-blocks", action="store_true", help="Suppress block-level logging")


def cmd(args: argparse.Namespace) -> int:
    emit_maturity_warning("firewall")

    from picosentry.firewall.proxy import FirewallConfig, FirewallProxy

    block_sevs = [s.strip().upper() for s in args.block_severities.split(",") if s.strip()]
    quarantine_sevs = [s.strip().upper() for s in args.quarantine_severities.split(",") if s.strip()]

    config = FirewallConfig(
        listen_port=args.port,
        upstream_npm=args.upstream_npm,
        upstream_pypi=args.upstream_pypi,
        block_severities=block_sevs,
        quarantine_severities=quarantine_sevs,
        cache_ttl_seconds=args.cache_ttl,
        scan_timeout_seconds=args.scan_timeout,
        log_blocks=not args.no_log_blocks,
    )

    proxy = FirewallProxy(config)
    proxy.serve()
    return 0


register("firewall", add_arguments, cmd)
