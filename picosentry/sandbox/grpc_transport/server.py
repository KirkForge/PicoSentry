"""PicoDome gRPC Server — serves PicoDome scan engine over gRPC.

Wraps the existing daemon's scan engine and exposes it via the
PicoDomeService gRPC service defined in proto/picodome.proto.

Uses lazy imports for grpcio so the module degrades gracefully
when grpcio is not installed.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from concurrent import futures
from typing import Any

from picosentry.sandbox.grpc_transport import is_grpc_available

logger = logging.getLogger("picodome.grpc_transport.server")


class _ScanEngine:
    """Thin wrapper around the existing L3+L4 scan pipeline.

    Dependency-injected so tests can replace it with a mock
    without needing the real scan engine.
    """

    def __init__(
        self,
        scan_fn: Callable | None = None,
        analyze_fn: Callable | None = None,
    ) -> None:
        self._scan_fn = scan_fn
        self._analyze_fn = analyze_fn

    def scan(self, command, policy=None, timeout=30.0, cwd=None, deterministic=False):
        """Run the L3 sandbox scan."""
        if self._scan_fn:
            return self._scan_fn(command=command, policy=policy, timeout=timeout, cwd=cwd, deterministic=deterministic)
        from picosentry.sandbox.l3.engine import sandbox_run

        return sandbox_run(command=command, policy=policy, timeout=timeout, cwd=cwd, deterministic=deterministic)

    def analyze(self, sandbox_result, rules=None, deterministic=False):
        """Run the L4 behavioral analysis."""
        if self._analyze_fn:
            return self._analyze_fn(sandbox_result, rules=rules, deterministic=deterministic)
        from picosentry.sandbox.l4.engine import create_default_engine
        from picosentry.sandbox.l4.profiler import profile_from_sandbox_result

        engine = create_default_engine()
        profile = profile_from_sandbox_result(sandbox_result)
        return engine.analyze(profile, rules=rules, deterministic=deterministic)


class PicoDomeGRPCServer:
    """gRPC server for PicoDome — serves the scan engine over gRPC.

    Usage::

        server = PicoDomeGRPCServer(port=50051)
        server.start()  # blocks

    Or with TLS::

        from picosentry.sandbox.mtls import MTLSConfig, create_ssl_context
        config = MTLSConfig(cert_path="server.crt", key_path="server.key", ca_path="ca.crt")
        server = PicoDomeGRPCServer(port=50051, mtls_config=config)
        server.start()

    If grpcio is not installed, start() will raise ImportError with
    a helpful message. Check ``is_grpc_available()`` before calling.
    """

    def __init__(
        self,
        host: str = "[::]",
        port: int = 50051,
        mtls_config: Any | None = None,
        max_workers: int = 10,
        scan_fn: Callable | None = None,
        analyze_fn: Callable | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._mtls_config = mtls_config
        self._max_workers = max_workers
        self._server = None
        self._servicer = None
        self._start_time = time.time()
        self._scan_engine = _ScanEngine(scan_fn=scan_fn, analyze_fn=analyze_fn)
        self._scan_count = 0

    def start(self) -> None:
        """Start the gRPC server (blocking).

        Raises:
            ImportError: If grpcio is not installed.
        """
        if not is_grpc_available():
            raise ImportError("grpcio is not installed. Install it with: pip install grpcio")

        import grpc

        from picosentry.sandbox.grpc_transport._servicer import PicoDomeServicer

        self._server = grpc.server(futures.ThreadPoolExecutor(max_workers=self._max_workers))
        self._servicer = PicoDomeServicer(
            scan_engine=self._scan_engine,
            start_time=self._start_time,
            scan_count_ref=self,
        )
        # Register servicer — we use the generated pb2/pb2_grpc if available,
        # otherwise fall back to manual registration
        try:
            from picosentry.sandbox.grpc_transport.proto import picodome_pb2_grpc as pb2_grpc

            pb2_grpc.add_PicoDomeServiceServicer_to_server(self._servicer, self._server)
        except ImportError:
            # Manual registration for when proto compilation is not done
            logger.warning(
                "Compiled protobuf stubs not found. "
                "Run: python -m grpc_tools.protoc -I src/picodome/grpc_transport/proto "
                "--python_out=src/picodome/grpc_transport/proto "
                "--grpc_python_out=src/picodome/grpc_transport/proto "
                "src/picodome/grpc_transport/proto/picodome.proto"
            )
            # Use generic handler registration
            from picosentry.sandbox.grpc_transport._servicer import add_servicer_manually

            add_servicer_manually(self._servicer, self._server)

        # Configure TLS if provided
        server_credentials = None
        if self._mtls_config is not None:
            server_credentials = self._create_server_credentials(self._mtls_config)

        address = f"{self._host}:{self._port}"
        if server_credentials:
            self._server.add_secure_port(address, server_credentials)
            logger.info("gRPC server starting with TLS on %s", address)
        else:
            self._server.add_insecure_port(address)
            logger.info("gRPC server starting (plaintext) on %s", address)

        # Audit log
        try:
            from picosentry.sandbox.audit import AuditEventType, get_audit_logger

            audit = get_audit_logger()
            audit.record(
                event_type=AuditEventType.DAEMON_START,
                actor="picodome-grpc-server",
                detail=f"gRPC server listening on {address}",
            )
        except Exception:
            pass

        self._server.start()
        logger.info("PicoDome gRPC server started on %s", address)
        self._server.wait_for_termination()

    def stop(self, grace: float = 5.0) -> None:
        """Gracefully stop the gRPC server.

        Args:
            grace: Seconds to allow in-flight RPCs to complete.
        """
        if self._server:
            self._server.stop(grace)

            # Audit log
            try:
                from picosentry.sandbox.audit import AuditEventType, get_audit_logger

                audit = get_audit_logger()
                audit.record(
                    event_type=AuditEventType.DAEMON_STOP,
                    actor="picodome-grpc-server",
                    detail="gRPC server stopped",
                )
            except Exception:
                pass

            logger.info("PicoDome gRPC server stopped")

    def _create_server_credentials(self, mtls_config) -> Any:
        """Create gRPC server credentials from MTLSConfig."""
        import grpc

        from picosentry.sandbox.mtls.context import MTLSConfig

        if not isinstance(mtls_config, MTLSConfig):
            logger.warning("mtls_config is not an MTLSConfig instance, skipping TLS")
            return None

        if mtls_config.dev_mode:
            logger.warning("Dev TLS mode — self-signed certs, DO NOT USE IN PRODUCTION")
            # In dev mode, we still need certs for gRPC; use the mtls module's dev context
            # For gRPC we need actual cert files, so dev mode with gRPC requires manual cert setup
            return None

        if not mtls_config.cert_path or not mtls_config.key_path:
            logger.warning("mTLS configured but cert/key paths missing")
            return None

        try:
            with open(mtls_config.cert_path, "rb") as f:
                cert_chain = f.read()
            with open(mtls_config.key_path, "rb") as f:
                private_key = f.read()

            if mtls_config.verify_client and mtls_config.ca_path:
                with open(mtls_config.ca_path, "rb") as f:
                    root_certs = f.read()
                # mTLS: require client cert
                credentials = grpc.ssl_server_credentials(
                    ((private_key, cert_chain),),
                    root_certificates=root_certs,
                    require_client_auth=True,
                )
            else:
                # Server TLS only (no client cert required)
                credentials = grpc.ssl_server_credentials(
                    ((private_key, cert_chain),),
                )

            logger.info("gRPC TLS credentials created (verify_client=%s)", mtls_config.verify_client)
            return credentials
        except Exception as e:
            logger.error("Failed to create gRPC TLS credentials: %s", e)
            return None
