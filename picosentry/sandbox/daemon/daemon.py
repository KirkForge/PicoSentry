from __future__ import annotations

import logging
import os
import signal
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

from picosentry.sandbox.audit import AuditEventType, get_audit_logger
from picosentry.sandbox.daemon.handler import PicoDomeHandler
from picosentry.sandbox.ratelimit import RateLimitConfig, TokenBucketLimiter

logger = logging.getLogger("picodome.daemon")


class _PicoDomeHTTPServer(ThreadingHTTPServer):
    """Threaded so one slow scan never blocks /health, /metrics or gossip.

    Reusable socket address so the daemon can restart quickly in tests and
    production.
    """

    allow_reuse_address = True
    timeout = 30


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
        self._server: ThreadingHTTPServer | None = None
        self._metrics_server: ThreadingHTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._metrics_thread: threading.Thread | None = None
        self._raw_socket: socket.socket | None = None  # unencrypted listener; TLS sockets are dups of it
        self._shutdown_event = threading.Event()
        self._reload_lock = threading.Lock()
        self._job_store_dir = job_store_dir or os.environ.get("PICODOME_JOB_STORE_DIR")
        self._store_backend = store_backend or os.environ.get("PICODOME_STORE_BACKEND", "jsonl")
        self._cluster_config = cluster_config or {}
        self._cluster_manager: Any | None = None

        backend = self._store_backend.lower()
        raw_store: Any
        if backend == "jsonl":
            from picosentry.sandbox.daemon.store import PersistentScanJobStore

            store_dir = Path(self._job_store_dir) if self._job_store_dir else None
            raw_store = PersistentScanJobStore(store_dir=store_dir)
            logger.info("Using JSONL job store backend")
        elif backend == "sqlite":
            from picosentry.sandbox.daemon.sqlite_store import SQLiteScanJobStore

            db_path = os.environ.get("PICODOME_SQLITE_PATH")
            raw_store = SQLiteScanJobStore(
                db_path=Path(db_path) if db_path else None,
            )
            logger.info("Using SQLite job store backend")
        elif backend == "redis":
            from picosentry.sandbox.daemon.redis_store import RedisScanJobStore

            raw_store = RedisScanJobStore(max_jobs=int(os.environ.get("PICODOME_REDIS_MAX_JOBS", "1000")))
            if not raw_store.available:
                # WO5.0.0-017: misconfiguration must be loud. Submits will be
                # rejected (503) until Redis is reachable; we do not crash here
                # so Redis can come up after the daemon.
                logger.error(
                    "PICODOME_STORE_BACKEND=redis but Redis is NOT reachable at %s "
                    "— scans will be rejected until it is",
                    raw_store.redis_url,
                )
            logger.info("Using Redis job store backend")
        else:
            # WO5.0.0-017: unknown backends used to silently fall back to jsonl.
            raise ValueError(f"Unknown PICODOME_STORE_BACKEND {self._store_backend!r} (expected: jsonl, sqlite, redis)")

        # Tenant scoping at the store boundary (WO4.0.0-010): the daemon never
        # exposes the raw store — every get/list/update carries tenant_id.
        from picosentry.sandbox.tenant.store import TenantAwareScanJobStore

        PicoDomeHandler.job_store = TenantAwareScanJobStore(raw_store)

        # Rebuild auth from the CURRENT environment. PicoDomeHandler's import-time
        # TokenAuth predates any PICODOME_API_TOKENS set after import (e.g.
        # create_app(tokens=…)), which silently no-opped (WO4.0.0-002).
        from picosentry.sandbox.auth import RBAC, TokenAuth

        PicoDomeHandler.rbac = RBAC()
        PicoDomeHandler.auth = TokenAuth(rbac=PicoDomeHandler.rbac)

        # Tenant registry from the CURRENT environment (WO5.0.0-001): the env
        # loader existed but had zero production callers — every daemon resolved
        # DEFAULT for all requests. Env vars: PICODOME_TENANTS,
        # PICODOME_TENANT_TOKEN_MAP, PICODOME_TENANT_OPERATOR_TOKENS.
        from picosentry.sandbox.tenant import load_tenants_from_env

        load_tenants_from_env()

        # Scan worker pool: bounded concurrent scans with queued→running→completed
        # job states instead of blocking a server thread per scan.
        scan_workers = max(1, int(os.environ.get("PICODOME_SCAN_WORKERS", "4")))
        scan_queue = max(0, int(os.environ.get("PICODOME_SCAN_QUEUE", "32")))
        self._scan_executor = ThreadPoolExecutor(max_workers=scan_workers, thread_name_prefix="picodome-scan")
        PicoDomeHandler.scan_executor = self._scan_executor
        PicoDomeHandler.scan_slots = threading.Semaphore(scan_workers + scan_queue)

        global_rps = float(os.environ.get("PICODOME_GLOBAL_RPS", "25.0"))
        rate_per_second = float(os.environ.get("PICODOME_RATE_PER_SECOND", "2.0"))
        PicoDomeHandler.rate_limiter = TokenBucketLimiter(
            RateLimitConfig(
                rate_per_second=rate_per_second,
                global_rps=global_rps,
            )
        )

        self._sinks = self._init_sinks()
        self._retention_thread: threading.Thread | None = None

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
                    # Bounded queue + drop counter so the webhook's synchronous
                    # retries can never stall the request thread (WO4.0.0-002).
                    from picosentry.sandbox.daemon.webhook_sink import QueuedWebhookSink

                    sinks.append(
                        QueuedWebhookSink(
                            WebhookSink(
                                config=config,
                                url=url,
                                auth_token=token,
                            )
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
        self._raw_socket = server.socket  # pristine listener; serving socket is a dup
        ssl_ctx = create_ssl_context()
        if ssl_ctx:
            server.socket = ssl_ctx.wrap_socket(self._raw_socket.dup(), server_side=True)
            logger.info("mTLS: TLS enabled on %s:%d", self._host, self._port)
        else:
            server.socket = self._raw_socket.dup()
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
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
            logger.debug("Audit log failed for daemon start", exc_info=True)

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

        # serve_forever always runs on its own thread so signal handlers never
        # call shutdown() from the serve_forever thread (deadlock, WO4.0.0-002).
        self._shutdown_event.clear()
        self._server_thread = threading.Thread(target=self._serve_loop, daemon=True, name="picodome-daemon-server")
        self._server_thread.start()
        self._start_retention_scheduler()

        if background:
            return

        # Foreground: park the main thread until a signal-driven stop().
        try:
            self._shutdown_event.wait()
        except KeyboardInterrupt:
            self.stop()

    def _serve_loop(self) -> None:
        server = self._server
        if server is None:
            return
        try:
            server.serve_forever(poll_interval=0.5)
        except Exception:
            if not self._shutdown_event.is_set():
                logger.exception("serve_forever loop crashed")

    def _retention_interval(self) -> float:
        """Retention cleanup cadence (WO4.0.0-019): run_cleanup was CLI-only;
        default daily, 0 disables."""
        try:
            return max(0.0, float(os.environ.get("PICODOME_RETENTION_INTERVAL_SECONDS", "86400")))
        except (ValueError, TypeError):
            return 86400.0

    def _start_retention_scheduler(self) -> None:
        interval = self._retention_interval()
        if interval <= 0:
            return

        def _loop() -> None:
            while not self._shutdown_event.wait(timeout=interval):
                try:
                    from picosentry.sandbox.retention import get_retention_manager

                    stats = get_retention_manager().run_cleanup()
                    if stats.get("files_removed"):
                        logger.info("Scheduled retention cleanup: %s", stats)
                except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
                    logger.debug("Scheduled retention cleanup failed", exc_info=True)

        self._retention_thread = threading.Thread(target=_loop, daemon=True, name="picodome-retention")
        self._retention_thread.start()
        logger.info("Retention cleanup scheduled every %.0fs", interval)

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
        self._shutdown_event.set()

        if self._server:
            self._server.shutdown()
            self._server.server_close()
            if self._server_thread is not None and self._server_thread.is_alive():
                self._server_thread.join(timeout=5.0)
            self._server = None
            self._server_thread = None
        if self._raw_socket is not None:
            try:
                self._raw_socket.close()
            except OSError:
                logger.debug("raw socket already closed", exc_info=True)
            self._raw_socket = None

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

        # Cancel queued scans; running ones finish in their worker threads.
        self._scan_executor.shutdown(wait=False, cancel_futures=True)
        if PicoDomeHandler.scan_executor is self._scan_executor:
            PicoDomeHandler.scan_executor = None
            PicoDomeHandler.scan_slots = None

        if self._retention_thread is not None and self._retention_thread.is_alive():
            self._retention_thread.join(timeout=2.0)
            self._retention_thread = None

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
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
            logger.debug("Audit log failed for daemon stop", exc_info=True)

        logger.info("PicoDome daemon stopped")

    def install_signal_handlers(self) -> None:

        def _handle_shutdown(signum: int, _frame: Any) -> None:
            sig_name = signal.Signals(signum).name
            logger.info("Received %s, shutting down gracefully...", sig_name)
            # Signal handlers run on the main thread, which may be inside
            # serve_forever's loop; server.shutdown() from that thread
            # deadlocks. Do the stop on a helper thread.
            threading.Thread(target=self.stop, daemon=True, name=f"picodome-signal-{sig_name}").start()

        signal.signal(signal.SIGTERM, _handle_shutdown)
        signal.signal(signal.SIGINT, _handle_shutdown)

        if hasattr(signal, "SIGHUP"):

            def _handle_hup(_signum: int, _frame: Any) -> None:
                logger.info("Received SIGHUP — reloading configuration")
                threading.Thread(target=self._reload_tls, daemon=True, name="picodome-sighup").start()

            signal.signal(signal.SIGHUP, _handle_hup)

    def _reload_tls(self) -> None:
        """SIGHUP: rebind the serving socket from the pristine RAW listener.

        The old code wrapped the already-SSL serving socket again (TLS-in-TLS,
        dead listener). Here the raw listener is dup'ed and wrapped fresh; the
        accept loop is stopped and restarted around the swap.
        """
        from picosentry.sandbox.mtls import reload_ssl_context

        with self._reload_lock:
            server = self._server
            raw = self._raw_socket
            if server is None or raw is None:
                logger.warning("SIGHUP: daemon not running, nothing to reload")
                return
            try:
                ctx = reload_ssl_context()
            except Exception as exc:
                logger.warning("SIGHUP reload failed: %s", exc)
                return

            try:
                server.shutdown()  # we are on a helper thread — safe
                old_sock = server.socket
                server.socket = ctx.wrap_socket(raw.dup(), server_side=True) if ctx else raw.dup()
                old_sock.close()
            except OSError as exc:
                logger.warning("SIGHUP socket rebind failed: %s", exc)
                return

            threading.Thread(target=self._serve_loop, daemon=True, name="picodome-daemon-server").start()
            logger.info("SIGHUP: TLS context reloaded and listener rebound")


__all__ = ["PicoDomeDaemon"]
