from __future__ import annotations

import logging
import signal
import ssl
import sys
from http.server import ThreadingHTTPServer as HTTPServer
from pathlib import Path
from typing import Any

from picosentry.scan.auth import AuthConfig, RateLimiter
from picosentry.scan.daemon.handler import HealthHandler, _request_counter as _request_counter
from picosentry.scan.daemon.tls import TLSConfig
from picosentry.scan.enterprise import EnterpriseViolation, enterprise_daemon_checks, is_enterprise_mode

logger = logging.getLogger("picosentry.daemon")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9090


def run_daemon(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    auth_config: AuthConfig | None = None,
    tls_config: TLSConfig | None = None,
) -> None:
    from picosentry.scan.audit import audit
    from picosentry.scan.metrics import increment, set_gauge

    if auth_config is None:
        from picosentry.scan.config import load_config

        try:
            cfg = load_config(Path.cwd())
            auth_config = AuthConfig.from_dict(cfg.daemon) if cfg.daemon else AuthConfig.from_env()
        except (OSError, RuntimeError, ValueError, TypeError, ImportError) as e:
            logger.debug("Config file not found or invalid, falling back to env vars: %s", e)
            auth_config = AuthConfig.from_env()

    rate_limiter = RateLimiter(rps=auth_config.rate_limit_rps)

    HealthHandler.auth_config = auth_config
    HealthHandler.rate_limiter = rate_limiter

    if is_enterprise_mode():
        try:
            warnings = enterprise_daemon_checks(auth_config.mode, host)
            for w in warnings:
                logger.warning(w)
        except EnterpriseViolation as e:
            logger.critical("Enterprise violation: %s", e)
            audit(
                "daemon.start_denied",
                target=f"{host}:{port}",
                outcome="failure",
                metadata={"reason": str(e)},
                fail_closed=True,
            )
            sys.exit(e.exit_code)
    elif auth_config.mode == "off":
        if host not in ("127.0.0.1", "localhost", "::1"):
            logger.critical(
                "SECURITY: auth=off on non-loopback interface %s — refusing to start. "
                "Bind to 127.0.0.1 or enable authentication (PICOSENTRY_AUTH_MODE=token).",
                host,
            )
            audit(
                "daemon.start_denied",
                target=f"{host}:{port}",
                outcome="failure",
                metadata={"reason": "auth=off on non-loopback"},
            )
            sys.exit(7)
        logger.warning(
            "Daemon running with auth=off (loopback only). Not recommended for production. "
            "Set PICOSENTRY_ENTERPRISE_MODE=1 to enforce auth."
        )

    set_gauge("daemon.active_requests", 0)
    increment("daemon.start")

    if tls_config is None:
        tls_config = TLSConfig.from_env()

    ssl_ctx = None
    if tls_config and tls_config.is_enabled():
        try:
            ssl_ctx = tls_config.to_ssl_context()
            logger.info("TLS enabled: cert=%s", tls_config.cert_file)
        except (FileNotFoundError, ssl.SSLError) as e:
            logger.critical("Failed to configure TLS: %s", e)
            sys.exit(8)

    server = HTTPServer((host, port), HealthHandler)
    if ssl_ctx:
        server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
    server_name = f"{host}:{port}"

    def shutdown(signum: int, _frame: Any) -> None:
        logger.info("Received signal %d, shutting down daemon...", signum)
        audit("daemon.stop", target=f"{host}:{port}", metadata={"signal": signum})
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    auth_summary = f"auth={auth_config.mode}"
    if auth_config.rate_limit_rps > 0:
        auth_summary += f" rate_limit={auth_config.rate_limit_rps}rps"
    public = ", ".join(auth_config.public_endpoints) if auth_config.mode != "off" else "all"

    proto = "https" if ssl_ctx else "http"
    logger.info("PicoSentry daemon starting on %s://%s (%s)", proto, server_name, auth_summary)
    logger.info("  Public endpoints: %s", public)
    if ssl_ctx:
        logger.info(
            "  TLS: cert=%s%s", tls_config.cert_file, f", mTLS CA: {tls_config.mtls_ca}" if tls_config.is_mtls() else ""
        )
    logger.info("  Health: %s://%s/health", proto, server_name)
    logger.info("  Metrics: %s://%s/metrics", proto, server_name)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        logger.info("Daemon stopped.")


__all__: list[str] = [
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "EnterpriseViolation",
    "HTTPServer",
    "HealthHandler",
    "TLSConfig",
    "_request_counter",
    "enterprise_daemon_checks",
    "is_enterprise_mode",
    "run_daemon",
]
