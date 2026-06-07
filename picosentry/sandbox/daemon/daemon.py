"""PicoDomeDaemon — HTTP API server orchestrator.

Extracted in v2.1.0 (refactor) from ``picosentry/sandbox/daemon/server.py``.

Drives the lifecycle of the HTTP server: configuration from environment,
job-store backend selection, audit-sink wiring, mTLS setup, signal handlers,
and graceful shutdown.
"""
from __future__ import annotations

import logging
import os
import signal
from http.server import HTTPServer
from pathlib import Path
from typing import Any

from picosentry.sandbox.audit import AuditEventType, get_audit_logger
from picosentry.sandbox.daemon.handler import PicoDomeHandler
from picosentry.sandbox.ratelimit import RateLimitConfig, TokenBucketLimiter

logger = logging.getLogger("picodome.daemon")


class PicoDomeDaemon:
    """PicoDome daemon — HTTP API server for sandbox-as-a-service.

    Usage::

        daemon = PicoDomeDaemon(host="127.0.0.1", port=8443)
        daemon.start()   # blocking
        # or
        daemon.start(background=True)

    Configuration:
    - ``PICODOME_DAEMON_HOST`` — bind address (default: 127.0.0.1)
    - ``PICODOME_DAEMON_PORT`` — bind port (default: 8443)
    - ``PICODOME_METRICS_PORT`` — separate metrics port (default: None, same as API)
    - ``PICODOME_API_TOKENS`` — comma-separated auth tokens
    - ``PICODOME_JOB_STORE_DIR`` — directory for persistent job storage
    - ``PICODOME_AUDIT_SINKS`` — comma-separated sink types (default: null)
      Available: null, file, webhook, syslog
    - ``PICODOME_WEBHOOK_URL`` — URL for webhook sink
    - ``PICODOME_WEBHOOK_TOKEN`` — Bearer token for webhook sink
    - ``PICODOME_SYSLOG_HOST`` — Syslog server host (default: 127.0.0.1)
    - ``PICODOME_SYSLOG_PORT`` — Syslog server port (default: 514)
    - ``PICODOME_FILE_SINK_DIR`` — Directory for file sink output
    - ``PICODOME_GLOBAL_RPS`` — global requests per second across all actors (default: 25.0)
    - ``PICODOME_RATE_PER_SECOND`` — per-actor requests per second (default: 2.0)
    - ``PICODOME_STORE_BACKEND`` — job store backend: jsonl (default) or sqlite
    - ``PICODOME_SQLITE_PATH`` — path to SQLite database (default: ~/.picodome/jobs.db)
    - ``PICODOME_CORS_ORIGINS`` — allowed CORS origins (default: *)
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        metrics_port: int | None = None,
        job_store_dir: str | None = None,
        store_backend: str | None = None,
    ) -> None:
        self._host = host or os.environ.get("PICODOME_DAEMON_HOST", "127.0.0.1")
        self._port = port or int(os.environ.get("PICODOME_DAEMON_PORT", "8443"))
        self._metrics_port = metrics_port or (
            int(os.environ["PICODOME_METRICS_PORT"]) if "PICODOME_METRICS_PORT" in os.environ else None
        )
        self._server: HTTPServer | None = None
        self._metrics_server: HTTPServer | None = None
        self._job_store_dir = job_store_dir or os.environ.get("PICODOME_JOB_STORE_DIR")
        self._store_backend = store_backend or os.environ.get("PICODOME_STORE_BACKEND", "jsonl")

        # Set up job store backend (jsonl or sqlite)
        backend = self._store_backend.lower()
        if backend == "sqlite":
            from picosentry.sandbox.daemon.sqlite_store import SQLiteScanJobStore

            db_path = os.environ.get("PICODOME_SQLITE_PATH")
            PicoDomeHandler.job_store = SQLiteScanJobStore(
                db_path=Path(db_path) if db_path else None,
            )
            logger.info("Using SQLite job store backend")
        else:
            from picosentry.sandbox.daemon.store import PersistentScanJobStore

            store_dir = Path(self._job_store_dir) if self._job_store_dir else None
            PicoDomeHandler.job_store = PersistentScanJobStore(store_dir=store_dir)
            logger.info("Using JSONL job store backend")

        # Set up rate limiter from environment
        global_rps = float(os.environ.get("PICODOME_GLOBAL_RPS", "25.0"))
        rate_per_second = float(os.environ.get("PICODOME_RATE_PER_SECOND", "2.0"))
        PicoDomeHandler.rate_limiter = TokenBucketLimiter(
            RateLimitConfig(
                rate_per_second=rate_per_second,
                global_rps=global_rps,
            )
        )

        # Set up audit sinks
        self._sinks = self._init_sinks()

    def _init_sinks(self) -> list:
        """Initialize audit sinks from environment configuration."""
        from picosentry.sandbox.audit.sinks import (
            AuditSink,
            FileSink,
            NullSink,
            SinkConfig,
            SyslogSink,
            WebhookSink,
        )

        sink_types = os.environ.get("PICODOME_AUDIT_SINKS", "null").split(",")
        sink_types = [s.strip().lower() for s in sink_types if s.strip()]

        sinks: list[AuditSink] = []
        for sink_type in sink_types:
            config = SinkConfig()
            try:
                if sink_type == "null":
                    sinks.append(NullSink(config=config))
                elif sink_type == "file":
                    sink_dir = os.environ.get("PICODOME_FILE_SINK_DIR")
                    sinks.append(
                        FileSink(
                            config=config,
                            output_dir=sink_dir,
                        )
                    )
                elif sink_type == "webhook":
                    url = os.environ.get("PICODOME_WEBHOOK_URL", "")
                    token = os.environ.get("PICODOME_WEBHOOK_TOKEN")
                    if not url:
                        logger.warning("WebhookSink: PICODOME_WEBHOOK_URL not set, skipping")
                        continue
                    sinks.append(
                        WebhookSink(
                            config=config,
                            url=url,
                            auth_token=token,
                        )
                    )
                elif sink_type == "syslog":
                    syslog_host = os.environ.get("PICODOME_SYSLOG_HOST", "127.0.0.1")
                    syslog_port = int(os.environ.get("PICODOME_SYSLOG_PORT", "514"))
                    sinks.append(
                        SyslogSink(
                            config=config,
                            host=syslog_host,
                            port=syslog_port,
                        )
                    )
                else:
                    logger.warning("Unknown audit sink type: '%s', skipping", sink_type)
            except Exception as exc:
                logger.warning("Failed to initialize sink '%s': %s", sink_type, exc)

        logger.info("Initialized %d audit sink(s): %s", len(sinks), [s.name for s in sinks])
        return sinks

    def start(self, background: bool = False) -> None:
        """Start the daemon HTTP server."""
        from picosentry.sandbox.mtls import create_ssl_context

        server = HTTPServer((self._host, self._port), PicoDomeHandler)
        ssl_ctx = create_ssl_context()
        if ssl_ctx:
            server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
            logger.info("mTLS: TLS enabled on %s:%d", self._host, self._port)
        self._server = server

        # Audit
        try:
            audit = get_audit_logger()
            # Wire sinks into the audit logger
            for sink in self._sinks:
                try:
                    sink.start()
                    audit.add_sink(sink)
                except Exception as exc:
                    logger.warning("Failed to start sink %s: %s", sink.name, exc)
            audit.record(
                event_type=AuditEventType.DAEMON_START,
                actor="picodome-daemon",
                detail=f"Listening on {self._host}:{self._port}",
            )
        except Exception:
            pass

        logger.info("PicoDome daemon starting on %s:%d", self._host, self._port)

        # If metrics port is separate, start a metrics-only listener
        if self._metrics_port and self._metrics_port != self._port:
            metrics_handler = type(
                "MetricsHandler",
                (PicoDomeHandler,),
                {"_metrics_only": True},
            )
            self._metrics_server = HTTPServer((self._host, self._metrics_port), metrics_handler)
            logger.info(
                "Metrics endpoint on separate port %s:%d (no auth required)",
                self._host,
                self._metrics_port,
            )
            if background:
                import threading

                metrics_thread = threading.Thread(target=self._metrics_server.serve_forever, daemon=True)
                metrics_thread.start()
            else:
                import threading

                metrics_thread = threading.Thread(target=self._metrics_server.serve_forever, daemon=True)
                metrics_thread.start()

        if background:
            import threading

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
        else:
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                self.stop()

    def stop(self) -> None:
        """Stop the daemon gracefully.

        Shuts down HTTP servers, stops audit sinks, and records a
        DAEMON_STOP audit event. Safe to call multiple times.
        """
        if self._server:
            self._server.shutdown()

        if self._metrics_server:
            self._metrics_server.shutdown()

        # Stop audit sinks
        for sink in self._sinks:
            try:
                sink.stop()
            except Exception as exc:
                logger.warning("Failed to stop sink %s: %s", sink.name, exc)

        try:
            audit = get_audit_logger()
            audit.record(
                event_type=AuditEventType.DAEMON_STOP,
                actor="picodome-daemon",
                detail="Daemon stopped",
            )
        except Exception:
            pass

        logger.info("PicoDome daemon stopped")

    def install_signal_handlers(self) -> None:
        """Install SIGTERM and SIGINT handlers for graceful shutdown.

        Call before start() when running in the foreground to ensure
        the daemon shuts down cleanly on termination signals.

        Usage::

            daemon = PicoDomeDaemon()
            daemon.install_signal_handlers()
            daemon.start()  # blocks; SIGTERM triggers graceful shutdown
        """

        def _handle_shutdown(signum: int, frame: Any) -> None:
            sig_name = signal.Signals(signum).name
            logger.info("Received %s, shutting down gracefully...", sig_name)
            self.stop()

        signal.signal(signal.SIGTERM, _handle_shutdown)
        signal.signal(signal.SIGINT, _handle_shutdown)

        # SIGHUP for config reload (graceful — reloads audit sinks and TLS certs)
        if hasattr(signal, "SIGHUP"):

            def _handle_hup(signum: int, frame: Any) -> None:
                logger.info("Received SIGHUP — reloading configuration")
                try:
                    from picosentry.sandbox.mtls import reload_ssl_context

                    ctx = reload_ssl_context()
                    if ctx and self._server:
                        self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
                        logger.info("SIGHUP: TLS context reloaded")
                except Exception as exc:
                    logger.warning("SIGHUP reload failed: %s", exc)

            signal.signal(signal.SIGHUP, _handle_hup)


__all__ = ["PicoDomeDaemon"]
