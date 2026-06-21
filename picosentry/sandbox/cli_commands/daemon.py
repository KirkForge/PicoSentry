from __future__ import annotations

import argparse
import os
import sys
from typing import Any

NAME = "daemon"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Start PicoDome daemon (HTTP API server)")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8443, help="Bind port (default: 8443)")
    parser.add_argument("--background", action="store_true", help="Run in background")
    parser.add_argument(
        "--transport",
        choices=["http", "grpc"],
        default="http",
        help="Transport protocol: http (default) or grpc",
    )
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
    parser.add_argument(
        "--cluster-token",
        default=os.environ.get("PICODOME_CLUSTER_TOKEN", ""),
        help="Shared secret required for cluster gossip membership (also PICODOME_CLUSTER_TOKEN env)",
    )
    parser.add_argument(
        "--cluster-address",
        default=os.environ.get("PICODOME_CLUSTER_ADDRESS", ""),
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
        default=os.environ.get("PICODOME_CLUSTER_BACKEND", "memory"),
        help="Cluster state backend (default: memory)",
    )
    parser.add_argument(
        "--cluster-heartbeat-interval",
        type=int,
        default=int(os.environ.get("PICODOME_CLUSTER_HEARTBEAT_INTERVAL", "10")),
        help="Cluster heartbeat interval in seconds (default: 10)",
    )
    parser.add_argument(
        "--cluster-heartbeat-timeout",
        type=int,
        default=int(os.environ.get("PICODOME_CLUSTER_HEARTBEAT_TIMEOUT", "30")),
        help="Cluster heartbeat timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--cluster-tls-cert",
        default=os.environ.get("PICODOME_CLUSTER_TLS_CERT", ""),
        help="Client certificate path for TLS/mTLS gossip (also PICODOME_CLUSTER_TLS_CERT env)",
    )
    parser.add_argument(
        "--cluster-tls-key",
        default=os.environ.get("PICODOME_CLUSTER_TLS_KEY", ""),
        help="Client private key path for TLS/mTLS gossip (also PICODOME_CLUSTER_TLS_KEY env)",
    )
    parser.add_argument(
        "--cluster-tls-ca",
        default=os.environ.get("PICODOME_CLUSTER_TLS_CA", ""),
        help="CA bundle path to verify peer certificates (also PICODOME_CLUSTER_TLS_CA env)",
    )


def cmd(args: argparse.Namespace) -> int:
    transport = getattr(args, "transport", "http")

    if transport == "grpc":
        from picosentry.sandbox.grpc_transport import PicoDomeGRPCServer, is_grpc_available

        if not is_grpc_available():
            print("Error: grpcio is not installed. Install with: pip install grpcio", file=sys.stderr)
            return 1

        grpc_port = getattr(args, "grpc_port", 50051)
        host = args.host

        mtls_config = None
        try:
            from picosentry.sandbox.mtls.context import MTLSConfig

            mtls_config = MTLSConfig.from_env()
            if not mtls_config.is_configured:
                mtls_config = None
        except Exception:
            pass

        server = PicoDomeGRPCServer(
            host=host,
            port=grpc_port,
            mtls_config=mtls_config,
        )
        try:
            print(f"Starting PicoDome gRPC daemon on {host}:{grpc_port}")
            server.start()
            return 0
        except KeyboardInterrupt:
            server.stop()
            return 0
        except Exception as e:
            print(f"gRPC daemon error: {e}", file=sys.stderr)
            return 1
    else:
        from picosentry.sandbox.daemon import PicoDomeDaemon

        store_backend = getattr(args, "store_backend", None) or "jsonl"
        metrics_port = getattr(args, "metrics_port", None)

        cluster_config: dict[str, Any] = {}
        if getattr(args, "cluster_token", ""):
            cluster_config["cluster_token"] = args.cluster_token
        if getattr(args, "cluster_address", ""):
            cluster_config["address"] = args.cluster_address
        if getattr(args, "cluster_port", None) is not None:
            cluster_config["port"] = args.cluster_port
        if getattr(args, "cluster_backend", ""):
            cluster_config["backend"] = args.cluster_backend
        if getattr(args, "cluster_heartbeat_interval", None) is not None:
            cluster_config["heartbeat_interval"] = args.cluster_heartbeat_interval
        if getattr(args, "cluster_heartbeat_timeout", None) is not None:
            cluster_config["heartbeat_timeout"] = args.cluster_heartbeat_timeout
        if getattr(args, "cluster_tls_cert", ""):
            cluster_config["tls_cert_path"] = args.cluster_tls_cert
        if getattr(args, "cluster_tls_key", ""):
            cluster_config["tls_key_path"] = args.cluster_tls_key
        if getattr(args, "cluster_tls_ca", ""):
            cluster_config["tls_ca_path"] = args.cluster_tls_ca

        daemon = PicoDomeDaemon(
            host=args.host,
            port=args.port,
            metrics_port=metrics_port,
            store_backend=store_backend,
            cluster_config=cluster_config or None,
        )

        if not args.background:
            daemon.install_signal_handlers()

        try:
            daemon.start(background=args.background)
            if args.background:
                print(f"PicoDome daemon started on {args.host}:{args.port}")
            return 0
        except KeyboardInterrupt:
            daemon.stop()
            return 0
        except Exception as e:
            print(f"Daemon error: {e}", file=sys.stderr)
            return 1


__all__ = ["NAME", "add_arguments", "cmd"]
