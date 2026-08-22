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
        choices=["jsonl", "sqlite", "redis"],
        default=None,
        help="Job store backend: jsonl (default), sqlite or redis (PICODOME_REDIS_URL)",
    )
    parser.add_argument(
        "--metrics-port",
        type=int,
        default=None,
        help="Separate port for /metrics endpoint (default: same as API port)",
    )
    parser.add_argument(
        "--cluster-token",
        default="",
        help="Shared secret required for cluster gossip membership (also PICODOME_CLUSTER_TOKEN env)",
    )
    parser.add_argument(
        "--cluster-address",
        default="",
        help="Cluster gossip bind address (default: daemon host)",
    )
    parser.add_argument(
        "--cluster-port",
        type=int,
        default=None,
        help="Cluster gossip port (default: daemon port)",
    )
    parser.add_argument(
        "--cluster-backend",
        choices=["memory", "sqlite"],
        default="memory",
        help="Cluster state backend (default: memory)",
    )
    parser.add_argument(
        "--cluster-heartbeat-interval",
        type=int,
        default=10,
        help="Cluster heartbeat interval in seconds (default: 10)",
    )
    parser.add_argument(
        "--cluster-heartbeat-timeout",
        type=int,
        default=30,
        help="Cluster heartbeat timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--cluster-tls-cert",
        default="",
        help="Client certificate path for TLS/mTLS gossip (also PICODOME_CLUSTER_TLS_CERT env)",
    )
    parser.add_argument(
        "--cluster-tls-key",
        default="",
        help="Client private key path for TLS/mTLS gossip (also PICODOME_CLUSTER_TLS_KEY env)",
    )
    parser.add_argument(
        "--cluster-tls-ca",
        default="",
        help="CA bundle path to verify peer certificates (also PICODOME_CLUSTER_TLS_CA env)",
    )


def cmd(args: argparse.Namespace) -> int:
    emit_maturity_warning("daemon")
    from picosentry.sandbox.cli_commands import daemon as _daemon_mod

    return _daemon_mod.cmd(args)


register("daemon", add_arguments, cmd)
