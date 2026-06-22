from __future__ import annotations

import logging
import os
import signal
import threading
from http.server import HTTPServer
from pathlib import Path
from typing import Any

from picosentry.sandbox.audit import AuditEventType, get_audit_logger
from picosentry.sandbox.daemon.handler import PicoDomeHandler
from picosentry.sandbox.ratelimit import RateLimitConfig, TokenBucketLimiter

logger = logging.getLogger("picodome.daemon")


class _PicoDomeHTTPServer(HTTPServer):
    """Reusable socket address so the daemon can restart quickly in tests and production."""

    allow_reuse_address = True


class PicoDomeDaemon:
    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        metrics_port: int | None = None,
        job_store_dir: str | None = None,
        store_backend: str | None = None,
        cluster_config: dict[str, Any] | None = None,
    ) -> None:
        self._host = host if host is not None else os.environ.get("PICODOME_DAEMON_HOST", "127.0.0.1")
        self._port = port if port is not None else int(os.environ.get("PICODOME_DAEMON_PORT", "8443"))
        self._metrics_port = (
            metrics_port
            if metrics_port is not None
            else (int(os.environ["PICODOME_METRICS_PORT"]) if "PICODOME_METRICS_PORT" in os.environ else None)
        )
        self._server: HTTPServer | None = None
        self._metrics_server: HTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._metrics_thread: threading.Thread | None = None
        self._job_store_dir = job_store_dir or os.environ.get("PICODOME_JOB_STORE_DIR")
        self._store_backend = store_backend or os.environ.get("PICODOME_STORE_BACKEND", "jsonl")
        self._cluster_config = cluster_config or {}
        self._cluster_manager: Any | None = None

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

        global_rps = float(os.environ.get("PICODOME_GLOBAL_RPS", "25.0"))
        rate_per_second = float(os.environ.get("PICODOME_RATE_PER_SECOND", "2.0"))
        PicoDomeHandler.rate_limiter = TokenBucketLimiter(
            RateLimitConfig(
                rate_per_second=rate_per_second,
                global_rps=global_rps,
            )
        )

        self._sinks = self._init_sinks()

    def _init_sinks(self) -> list:
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
        from picosentry.sandbox.mtls import create_ssl_context

        self._start_cluster_manager()

        server = _PicoDomeHTTPServer((self._host, self._port), PicoDomeHandler)
        ssl_ctx = create_ssl_context()
        if ssl_ctx:
            server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
            logger.info("mTLS: TLS enabled on %s:%d", self._host, self._port)
        self._server = server

        try:
            audit = get_audit_logger()

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

        if self._metrics_port and self._metrics_port != self._port:
            metrics_handler = type(
                "MetricsHandler",
                (PicoDomeHandler,),
                {"_metrics_only": True},
            )
            self._metrics_server = _PicoDomeHTTPServer((self._host, self._metrics_port), metrics_handler)
            logger.info(
                "Metrics endpoint on separate port %s:%d (no auth required)",
                self._host,
                self._metrics_port,
            )
            self._metrics_thread = threading.Thread(
                target=self._metrics_server.serve_forever, daemon=True, name="picodome-metrics-server"
            )
            self._metrics_thread.start()

        if background:
            self._server_thread = threading.Thread(
                target=server.serve_forever, daemon=True, name="picodome-daemon-server"
            )
            self._server_thread.start()
        else:
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                self.stop()

    def _start_cluster_manager(self) -> None:
        """Start the cluster manager if cluster mode is configured."""
        token = self._cluster_config.get("cluster_token") or os.environ.get("PICODOME_CLUSTER_TOKEN", "")
        if not token:
            return

        from picosentry.sandbox.cluster.backends import MemoryStateBackend, SQLiteStateBackend
        from picosentry.sandbox.cluster.manager import setup_cluster_manager
        from picosentry.sandbox.cluster.models import DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_HEARTBEAT_TIMEOUT

        backend_name = self._cluster_config.get("backend", os.environ.get("PICODOME_CLUSTER_BACKEND", "memory"))
        backend = SQLiteStateBackend() if backend_name == "sqlite" else MemoryStateBackend()

        cluster_address = self._cluster_config.get("address", os.environ.get("PICODOME_CLUSTER_ADDRESS", self._host))
        cluster_port = self._cluster_config.get("port")
        if cluster_port is None:
            cluster_port = int(os.environ.get("PICODOME_CLUSTER_PORT", str(self._port)))

        heartbeat_interval = self._cluster_config.get(
            "heartbeat_interval",
            int(os.environ.get("PICODOME_CLUSTER_HEARTBEAT_INTERVAL", str(DEFAULT_HEARTBEAT_INTERVAL))),
        )
        heartbeat_timeout = self._cluster_config.get(
            "heartbeat_timeout",
            int(os.environ.get("PICODOME_CLUSTER_HEARTBEAT_TIMEOUT", str(DEFAULT_HEARTBEAT_TIMEOUT))),
        )

        self._cluster_manager = setup_cluster_manager(
            address=cluster_address,
            port=cluster_port,
            backend=backend,
            heartbeat_interval=heartbeat_interval,
            heartbeat_timeout=heartbeat_timeout,
            cluster_token=token,
            tls_cert_path=self._cluster_config.get("tls_cert_path", os.environ.get("PICODOME_CLUSTER_TLS_CERT", "")),
            tls_key_path=self._cluster_config.get("tls_key_path", os.environ.get("PICODOME_CLUSTER_TLS_KEY", "")),
            tls_ca_path=self._cluster_config.get("tls_ca_path", os.environ.get("PICODOME_CLUSTER_TLS_CA", "")),
        )
        self._cluster_manager.start()
        logger.info(
            "Cluster manager started on %s:%d (backend=%s)",
            cluster_address,
            cluster_port,
            backend_name,
        )

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            if self._server_thread is not None and self._server_thread.is_alive():
                self._server_thread.join(timeout=5.0)
            self._server = None
            self._server_thread = None

        if self._metrics_server:
            self._metrics_server.shutdown()
            self._metrics_server.server_close()
            if self._metrics_thread is not None and self._metrics_thread.is_alive():
                self._metrics_thread.join(timeout=5.0)
            self._metrics_server = None
            self._metrics_thread = None

        if self._cluster_manager is not None:
            try:
                self._cluster_manager.stop()
            except Exception as exc:
                logger.warning("Failed to stop cluster manager: %s", exc)
            self._cluster_manager = None

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

        def _handle_shutdown(signum: int, _frame: Any) -> None:
            sig_name = signal.Signals(signum).name
            logger.info("Received %s, shutting down gracefully...", sig_name)
            self.stop()

        signal.signal(signal.SIGTERM, _handle_shutdown)
        signal.signal(signal.SIGINT, _handle_shutdown)

        if hasattr(signal, "SIGHUP"):

            def _handle_hup(_signum: int, _frame: Any) -> None:
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
