from __future__ import annotations

import argparse

NAME = "daemon"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Start HTTP daemon for health checks and metrics")
    parser.add_argument("--port", "-p", type=int, default=9090, help="Listen port (default: 9090)")
    parser.add_argument("--host", "-H", type=str, default="127.0.0.1", help="Listen host (default: 127.0.0.1)")
    parser.add_argument(
        "--auth-mode",
        type=str,
        choices=["off", "token", "oidc"],
        default=None,
        help="Auth mode: off (default), token, or oidc",
    )
    parser.add_argument("--auth-token", type=str, default=None, help="Static bearer token (token auth mode)")
    parser.add_argument("--rate-limit", type=float, default=None, help="Max requests per second per IP (0=unlimited)")
    parser.add_argument("--enterprise", action="store_true", help="Enable enterprise mode.")
    parser.add_argument(
        "--tls-cert", type=str, default=None, help="Path to TLS certificate file (PEM format) for HTTPS daemon."
    )
    parser.add_argument(
        "--tls-key", type=str, default=None, help="Path to TLS private key file (PEM format) for HTTPS daemon."
    )
    parser.add_argument(
        "--mtls-ca", type=str, default=None, help="Path to CA certificate for mutual TLS client verification."
    )


def cmd(args: argparse.Namespace) -> int:
    from picosentry.scan.auth import AuthConfig
    from picosentry.scan.daemon import TLSConfig, run_daemon
    from picosentry.scan.enterprise import is_enterprise_mode


    auth_config = AuthConfig.from_env()
    if getattr(args, "auth_mode", None) is not None:
        auth_config.mode = args.auth_mode
    if getattr(args, "auth_token", None) is not None:
        auth_config.token = args.auth_token
    if getattr(args, "rate_limit", None) is not None:
        auth_config.rate_limit_rps = args.rate_limit


    if getattr(args, "enterprise", False) and not is_enterprise_mode():
        import os

        os.environ["PICOSENTRY_ENTERPRISE_MODE"] = "1"


    tls_config = TLSConfig(
        cert_file=getattr(args, "tls_cert", None) or "",
        key_file=getattr(args, "tls_key", None) or "",
        mtls_ca=getattr(args, "mtls_ca", None) or "",
    )
    run_daemon(args.host, args.port, auth_config=auth_config, tls_config=tls_config)
    return 0


__all__ = ["NAME", "add_arguments", "cmd"]
