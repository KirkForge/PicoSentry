"""PicoDome gRPC Client — connects to an PicoDome gRPC server.

Provides both synchronous and asynchronous scan methods, with
timeout and retry logic, and TLS/mTLS support.

Uses lazy imports for grpcio so the module degrades gracefully
when grpcio is not installed.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from picosentry.sandbox.grpc_transport import is_grpc_available

logger = logging.getLogger("picodome.grpc_transport.client")


class ScanResult:
    """Result of a gRPC scan call.

    Mirrors the key fields from the daemon's scan response,
    but as a plain Python object (no dependency on proto classes).
    """

    def __init__(
        self,
        result_json: str = "",
        exit_code: int = 0,
        verdict: str = "",
        job_id: str = "",
        l3_verdict: str = "",
        l4_verdict: str = "",
        findings_count: int = 0,
    ) -> None:
        self.result_json = result_json
        self.exit_code = exit_code
        self.verdict = verdict
        self.job_id = job_id
        self.l3_verdict = l3_verdict
        self.l4_verdict = l4_verdict
        self.findings_count = findings_count

    def to_dict(self) -> dict[str, Any]:
        return {
            "result_json": self.result_json,
            "exit_code": self.exit_code,
            "verdict": self.verdict,
            "job_id": self.job_id,
            "l3_verdict": self.l3_verdict,
            "l4_verdict": self.l4_verdict,
            "findings_count": self.findings_count,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ScanResult:
        return cls(
            result_json=d.get("result_json", ""),
            exit_code=d.get("exit_code", 0),
            verdict=d.get("verdict", ""),
            job_id=d.get("job_id", ""),
            l3_verdict=d.get("l3_verdict", ""),
            l4_verdict=d.get("l4_verdict", ""),
            findings_count=d.get("findings_count", 0),
        )


class PicoDomeGRPCClient:
    """gRPC client for PicoDome — connects to an PicoDome gRPC server.

    Usage::

        client = PicoDomeGRPCClient(target="localhost:50051")
        result = client.scan(command=["echo", "hello"])

    Or with TLS::

        from picosentry.sandbox.mtls import MTLSConfig
        config = MTLSConfig(cert_path="client.crt", key_path="client.key", ca_path="ca.crt")
        client = PicoDomeGRPCClient(target="localhost:50051", mtls_config=config)

    If grpcio is not installed, calling scan() will raise ImportError.
    Check ``is_grpc_available()`` before instantiating.
    """

    def __init__(
        self,
        target: str = "localhost:50051",
        mtls_config: Any | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ) -> None:
        self._target = target
        self._mtls_config = mtls_config
        self._timeout = timeout
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._channel = None
        self._stub = None

    def _ensure_channel(self) -> None:
        """Lazily create the gRPC channel and stub."""
        if self._channel is not None:
            return

        if not is_grpc_available():
            raise ImportError("grpcio is not installed. Install it with: pip install grpcio")

        import grpc

        credentials = self._create_client_credentials(self._mtls_config)

        if credentials:
            self._channel = grpc.secure_channel(self._target, credentials)
            logger.info("gRPC client connected (TLS) to %s", self._target)
        else:
            self._channel = grpc.insecure_channel(self._target)
            logger.info("gRPC client connected (plaintext) to %s", self._target)

        # Try to use generated stubs, fall back to manual
        try:
            from picosentry.sandbox.grpc_transport.proto import picodome_pb2_grpc as pb2_grpc

            self._stub = pb2_grpc.PicoDomeServiceStub(self._channel)
        except ImportError:
            logger.warning("Compiled protobuf stubs not found, using manual stub")
            self._stub = None

    def _create_client_credentials(self, mtls_config) -> Any:
        """Create gRPC client credentials from MTLSConfig."""
        if mtls_config is None:
            return None

        from picosentry.sandbox.mtls.context import MTLSConfig

        if not isinstance(mtls_config, MTLSConfig):
            logger.warning("mtls_config is not an MTLSConfig instance, skipping TLS")
            return None

        if mtls_config.dev_mode:
            # Dev mode: use insecure channel
            return None

        if not mtls_config.cert_path or not mtls_config.key_path:
            logger.warning("mTLS configured but cert/key paths missing")
            return None

        import grpc

        try:
            with open(mtls_config.cert_path, "rb") as f:
                cert_chain = f.read()
            with open(mtls_config.key_path, "rb") as f:
                private_key = f.read()

            if mtls_config.ca_path:
                with open(mtls_config.ca_path, "rb") as f:
                    root_certs = f.read()
            else:
                root_certs = None

            credentials = grpc.ssl_channel_credentials(
                root_certificates=root_certs,
                private_key=private_key,
                certificate_chain=cert_chain,
            )
            logger.info("gRPC client TLS credentials created")
            return credentials
        except Exception as e:
            logger.error("Failed to create gRPC client TLS credentials: %s", e)
            return None

    def scan(
        self,
        command: list[str],
        policy: str | None = None,
        timeout: float | None = None,
        cwd: str | None = None,
    ) -> ScanResult:
        """Submit a scan request synchronously with retry logic.

        Args:
            command: Command to execute (e.g. ["echo", "hello"]).
            policy: Policy name or JSON-encoded policy.
            timeout: Timeout in seconds (overrides client default).
            cwd: Working directory.

        Returns:
            ScanResult with the scan outcome.

        Raises:
            ImportError: If grpcio is not installed.
            ConnectionError: If all retries fail.
        """
        self._ensure_channel()

        scan_timeout = timeout or self._timeout
        last_error = None

        for attempt in range(1, self._max_retries + 1):
            try:
                return self._do_scan(command, policy, scan_timeout, cwd)
            except Exception as e:
                last_error = e
                if attempt < self._max_retries:
                    logger.warning(
                        "Scan attempt %d/%d failed: %s — retrying in %.1fs",
                        attempt,
                        self._max_retries,
                        e,
                        self._retry_delay,
                    )
                    time.sleep(self._retry_delay)
                else:
                    logger.error("All %d scan attempts failed", self._max_retries)

        raise ConnectionError(f"Failed to scan after {self._max_retries} attempts: {last_error}")

    def _do_scan(
        self,
        command: list[str],
        policy: str | None,
        timeout: float,
        cwd: str | None,
    ) -> ScanResult:
        """Execute a single scan RPC call."""
        try:
            from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2
            from picosentry.sandbox.grpc_transport.proto import picodome_pb2_grpc as pb2_grpc

            request = pb2.ScanRequest(
                command=command,
                policy=policy or "",
                timeout=timeout,
                cwd=cwd or "",
            )
            if self._stub is None:
                self._stub = pb2_grpc.PicoDomeServiceStub(self._channel)

            response = self._stub.Scan(request, timeout=timeout)

            return ScanResult(
                result_json=response.result_json,
                exit_code=response.exit_code,
                verdict=response.verdict,
                job_id=response.job_id,
                l3_verdict=response.l3_verdict,
                l4_verdict=response.l4_verdict,
                findings_count=response.findings_count,
            )
        except ImportError:
            # Proto stubs not compiled — use manual call
            return self._do_scan_manual(command, policy, timeout, cwd)

    def _do_scan_manual(
        self,
        command: list[str],
        policy: str | None,
        timeout: float,
        cwd: str | None,
    ) -> ScanResult:
        """Manual scan call when proto stubs are not compiled.

        This uses the raw gRPC call method as a fallback.
        """
        import grpc

        # Serialize request manually (simple JSON-based approach for fallback)
        request_data = json.dumps(
            {
                "command": command,
                "policy": policy or "",
                "timeout": timeout,
                "cwd": cwd or "",
            }
        ).encode("utf-8")

        # Use generic unary-unary call
        try:
            response_data = self._channel.unary_unary(
                "/picodome.PicoDomeService/Scan",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )(request_data, timeout=timeout)

            resp = json.loads(response_data.decode("utf-8"))
            return ScanResult.from_dict(resp)
        except grpc.RpcError as e:
            logger.error("gRPC Scan RPC failed: %s", e)
            raise

    async def scan_async(
        self,
        command: list[str],
        policy: str | None = None,
        timeout: float | None = None,
        cwd: str | None = None,
    ) -> ScanResult:
        """Submit a scan request asynchronously.

        Uses asyncio.to_thread to run the synchronous gRPC call in a
        thread pool, allowing concurrent scans without blocking the
        event loop. Falls back to synchronous scan if asyncio is not
        available.
        """
        import asyncio

        try:
            loop = asyncio.get_running_loop()
            logger.debug("scan_async: running synchronous scan in thread pool")
            return await loop.run_in_executor(
                None, self.scan, command, policy, timeout, cwd
            )
        except RuntimeError:
            logger.debug("scan_async: no event loop, delegating to synchronous scan")
            return self.scan(command=command, policy=policy, timeout=timeout, cwd=cwd)

    def health(self) -> dict[str, Any]:
        """Check the health of the gRPC server."""
        self._ensure_channel()

        try:
            from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2
            from picosentry.sandbox.grpc_transport.proto import picodome_pb2_grpc as pb2_grpc

            request = pb2.HealthCheckRequest()
            if self._stub is None:
                self._stub = pb2_grpc.PicoDomeServiceStub(self._channel)
            response = self._stub.Health(request, timeout=5.0)

            return {
                "healthy": response.healthy,
                "version": response.version,
                "detail": response.detail,
                "uptime_seconds": response.uptime_seconds,
            }
        except ImportError:
            # Proto stubs not compiled
            import grpc

            try:
                response_data = self._channel.unary_unary(
                    "/picodome.PicoDomeService/Health",
                    request_serializer=lambda x: x,
                    response_deserializer=lambda x: x,
                )(b"", timeout=5.0)
                return json.loads(response_data.decode("utf-8"))
            except grpc.RpcError as e:
                logger.error("gRPC Health RPC failed: %s", e)
                return {"healthy": False, "detail": str(e)}

    def get_policy(self, name: str, version: int | None = None) -> dict[str, Any]:
        """Get a policy by name."""
        self._ensure_channel()

        try:
            from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2
            from picosentry.sandbox.grpc_transport.proto import picodome_pb2_grpc as pb2_grpc

            request = pb2.PolicyGetRequest(name=name, version=version or 0)
            if self._stub is None:
                self._stub = pb2_grpc.PicoDomeServiceStub(self._channel)
            response = self._stub.GetPolicy(request, timeout=10.0)

            return {
                "policy_json": response.policy_json,
                "name": response.name,
                "version": response.version,
            }
        except ImportError:
            import grpc

            request_data = json.dumps({"name": name, "version": version or 0}).encode("utf-8")
            try:
                response_data = self._channel.unary_unary(
                    "/picodome.PicoDomeService/GetPolicy",
                    request_serializer=lambda x: x,
                    response_deserializer=lambda x: x,
                )(request_data, timeout=10.0)
                return json.loads(response_data.decode("utf-8"))
            except grpc.RpcError as e:
                logger.error("gRPC GetPolicy RPC failed: %s", e)
                raise

    def query_audit(
        self,
        event_type: str | None = None,
        actor: str | None = None,
        target: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Query the audit log via gRPC."""
        self._ensure_channel()

        try:
            from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2
            from picosentry.sandbox.grpc_transport.proto import picodome_pb2_grpc as pb2_grpc

            request = pb2.AuditQueryRequest(
                event_type=event_type or "",
                actor=actor or "",
                target=target or "",
                since=since or "",
                until=until or "",
                limit=limit,
            )
            if self._stub is None:
                self._stub = pb2_grpc.PicoDomeServiceStub(self._channel)
            response = self._stub.QueryAudit(request, timeout=10.0)

            return {
                "events_json": response.events_json,
                "count": response.count,
            }
        except ImportError:
            import grpc

            request_data = json.dumps(
                {
                    "event_type": event_type or "",
                    "actor": actor or "",
                    "target": target or "",
                    "since": since or "",
                    "until": until or "",
                    "limit": limit,
                }
            ).encode("utf-8")
            try:
                response_data = self._channel.unary_unary(
                    "/picodome.PicoDomeService/QueryAudit",
                    request_serializer=lambda x: x,
                    response_deserializer=lambda x: x,
                )(request_data, timeout=10.0)
                return json.loads(response_data.decode("utf-8"))
            except grpc.RpcError as e:
                logger.error("gRPC QueryAudit RPC failed: %s", e)
                raise

    def close(self) -> None:
        """Close the gRPC channel."""
        if self._channel is not None:
            try:
                self._channel.close()
            except Exception:
                pass
            self._channel = None
            self._stub = None

    def __enter__(self) -> PicoDomeGRPCClient:
        return self

    def __exit__(self, *args) -> None:
        self.close()
