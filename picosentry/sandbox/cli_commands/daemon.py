from __future__ import annotations

import argparse
import sys

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

        daemon = PicoDomeDaemon(
            host=args.host,
            port=args.port,
            metrics_port=metrics_port,
            store_backend=store_backend,
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
