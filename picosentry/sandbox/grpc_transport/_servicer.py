"""PicoDome gRPC Servicer — implements the PicoDomeService RPCs.

This module contains the actual RPC handler implementations.
It is imported lazily by server.py only when grpcio is available.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

from picosentry.sandbox import __version__

logger = logging.getLogger("picodome.grpc_transport.servicer")


class PicoDomeServicer:
    """Implementation of the PicoDomeService gRPC service.

    Delegates actual scanning to the injected scan engine,
    and logs all RPCs to the audit module.
    """

    def __init__(self, scan_engine, start_time: float, scan_count_ref: Any) -> None:
        """Initialize the servicer.

        Args:
            scan_engine: _ScanEngine instance wrapping L3+L4 pipeline.
            start_time: Server start time (monotonic).
            scan_count_ref: Reference to the server object (for incrementing scan count).
        """
        self._scan_engine = scan_engine
        self._start_time = start_time
        self._scan_count_ref = scan_count_ref

    def Scan(self, request, context):
        """Handle a Scan RPC."""
        self._audit_log("SCAN_START", detail=f"command={list(request.command)}")

        try:
            # Extract fields from request
            command = list(request.command) if hasattr(request, "command") else []
            policy_name = request.policy if hasattr(request, "policy") else ""
            timeout = request.timeout if hasattr(request, "timeout") and request.timeout else 30.0
            cwd = request.cwd if hasattr(request, "cwd") and request.cwd else None

            # Load policy if specified
            policy = None
            if policy_name:
                try:
                    from pathlib import Path

                    from picosentry.sandbox.l3.policy import load_policy

                    policy = load_policy(Path(policy_name))
                except Exception:
                    logger.debug("Policy '%s' not found, using default", policy_name)

            # Run L3 sandbox
            sandbox_result = self._scan_engine.scan(
                command=command,
                policy=policy,
                timeout=timeout,
                cwd=cwd,
                deterministic=False,
            )

            # Run L4 analysis
            analysis_result = self._scan_engine.analyze(
                sandbox_result,
                deterministic=False,
            )

            # Build response
            result = {
                "job_id": f"grpc-{uuid.uuid4().hex}",
                "sandbox": sandbox_result.to_dict(deterministic=False),
                "analysis": analysis_result.to_dict(deterministic=False),
                "l3_verdict": sandbox_result.overall_verdict.value,
                "l4_verdict": analysis_result.overall_verdict.value,
                "findings_count": len(analysis_result.findings),
            }

            # Increment scan counter
            if hasattr(self._scan_count_ref, "_scan_count"):
                self._scan_count_ref._scan_count += 1

            self._audit_log(
                "SCAN_COMPLETE",
                detail=f"l3={sandbox_result.overall_verdict.value} l4={analysis_result.overall_verdict.value}",
            )

            # Try to use proto response, fall back to manual
            try:
                from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2

                return pb2.ScanResponse(
                    result_json=json.dumps(result, sort_keys=True, default=str),
                    exit_code=sandbox_result.exit_code,
                    verdict=analysis_result.overall_verdict.value,
                    job_id=result["job_id"],
                    l3_verdict=sandbox_result.overall_verdict.value,
                    l4_verdict=analysis_result.overall_verdict.value,
                    findings_count=len(analysis_result.findings),
                )
            except ImportError:
                # Return a dict-like response for manual handling
                return _DictProxy(
                    {
                        "result_json": json.dumps(result, sort_keys=True, default=str),
                        "exit_code": sandbox_result.exit_code,
                        "verdict": analysis_result.overall_verdict.value,
                        "job_id": result["job_id"],
                        "l3_verdict": sandbox_result.overall_verdict.value,
                        "l4_verdict": analysis_result.overall_verdict.value,
                        "findings_count": len(analysis_result.findings),
                    }
                )

        except Exception as e:
            logger.exception("Scan RPC failed: %s", e)
            self._audit_log("SCAN_ERROR", detail=str(e))

            # Return error response — works without grpcio
            error_result = {
                "result_json": json.dumps({"error": str(e)}),
                "exit_code": 1,
                "verdict": "ERROR",
                "job_id": "",
                "l3_verdict": "ERROR",
                "l4_verdict": "ERROR",
                "findings_count": 0,
            }

            try:
                from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2

                return pb2.ScanResponse(
                    result_json=error_result["result_json"],
                    exit_code=error_result["exit_code"],
                    verdict=error_result["verdict"],
                    job_id=error_result["job_id"],
                    l3_verdict=error_result["l3_verdict"],
                    l4_verdict=error_result["l4_verdict"],
                    findings_count=error_result["findings_count"],
                )
            except ImportError:
                # No protobuf stubs and no grpcio — return dict proxy
                return _DictProxy(error_result)

    def Health(self, request, context):
        """Handle a Health RPC."""
        uptime = int(time.time() - self._start_time)

        try:
            from picosentry.sandbox.health import check_health

            checks = check_health()
            all_healthy = all(c.healthy for c in checks)
        except Exception:
            all_healthy = True

        try:
            from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2

            return pb2.HealthCheckResponse(
                healthy=all_healthy,
                version=__version__,
                detail=f"Uptime: {uptime}s",
                uptime_seconds=uptime,
            )
        except ImportError:
            return _DictProxy(
                {
                    "healthy": all_healthy,
                    "version": __version__,
                    "detail": f"Uptime: {uptime}s",
                    "uptime_seconds": uptime,
                }
            )

    def GetPolicy(self, request, context):
        """Handle a GetPolicy RPC."""
        name = request.name if hasattr(request, "name") else ""

        try:
            from picosentry.sandbox.policy_versioned import get_policy_store

            store = get_policy_store()
            version = request.version if hasattr(request, "version") and request.version else None
            pv = store.load(name, version=version if version and version > 0 else None)
            if pv:
                policy_json = json.dumps(pv.to_dict(), sort_keys=True)
                policy_version = pv.version
            else:
                policy_json = "{}"
                policy_version = 0
        except Exception as e:
            policy_json = json.dumps({"error": str(e)})
            policy_version = 0

        try:
            from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2

            return pb2.PolicyGetResponse(
                policy_json=policy_json,
                name=name,
                version=policy_version,
            )
        except ImportError:
            return _DictProxy(
                {
                    "policy_json": policy_json,
                    "name": name,
                    "version": policy_version,
                }
            )

    def QueryAudit(self, request, context):
        """Handle a QueryAudit RPC."""
        event_type = request.event_type if hasattr(request, "event_type") else ""
        actor = request.actor if hasattr(request, "actor") else ""
        target = request.target if hasattr(request, "target") else ""
        since = request.since if hasattr(request, "since") else ""
        until = request.until if hasattr(request, "until") else ""
        limit = request.limit if hasattr(request, "limit") and request.limit else 100

        try:
            from picosentry.sandbox.audit import AuditEventType, get_audit_logger

            audit = get_audit_logger()

            et = None
            if event_type:
                try:
                    et = AuditEventType(event_type)
                except ValueError:
                    pass

            events = audit.query(
                event_type=et,
                actor=actor or None,
                target=target or None,
                since=since or None,
                until=until or None,
                limit=limit,
            )
            events_json = json.dumps([e.to_dict() for e in events], sort_keys=True, default=str)
            count = len(events)
        except Exception as e:
            events_json = json.dumps({"error": str(e)})
            count = 0

        try:
            from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2

            return pb2.AuditQueryResponse(
                events_json=events_json,
                count=count,
            )
        except ImportError:
            return _DictProxy(
                {
                    "events_json": events_json,
                    "count": count,
                }
            )

    def _audit_log(self, event_type: str, detail: str = "") -> None:
        """Log an event to the audit module."""
        try:
            from picosentry.sandbox.audit import AuditEventType, get_audit_logger

            audit = get_audit_logger()
            # Map string event type to enum
            try:
                et = AuditEventType(event_type)
            except ValueError:
                et = AuditEventType.SCAN_START  # fallback
            audit.record(
                event_type=et,
                actor="picodome-grpc",
                detail=detail,
            )
        except Exception:
            logger.debug("Audit log failed for event %s", event_type)


class _DictProxy:
    """Simple dict-like proxy for when proto stubs are not compiled.

    Allows tests and manual mode to work without protobuf compilation.
    """

    def __init__(self, data: dict) -> None:
        self._data = data

    def __getattr__(self, name: str):
        if name.startswith("_"):
            return super().__getattribute__(name)
        return self._data.get(name, "")

    def __repr__(self) -> str:
        return f"_DictProxy({self._data})"


def add_servicer_manually(servicer, server):
    """Add servicer to a gRPC server using manual method registration.

    Used when compiled proto stubs are not available.
    Creates generic RPC handlers for each method.
    """
    import grpc

    service_name = "picodome.PicoDomeService"

    rpc_method_handlers = {
        "Scan": grpc.unary_unary_rpc_method_handler(
            servicer.Scan,
            request_deserializer=lambda x: x,
            response_serializer=lambda x: x,
        ),
        "Health": grpc.unary_unary_rpc_method_handler(
            servicer.Health,
            request_deserializer=lambda x: x,
            response_serializer=lambda x: x,
        ),
        "GetPolicy": grpc.unary_unary_rpc_method_handler(
            servicer.GetPolicy,
            request_deserializer=lambda x: x,
            response_serializer=lambda x: x,
        ),
        "QueryAudit": grpc.unary_unary_rpc_method_handler(
            servicer.QueryAudit,
            request_deserializer=lambda x: x,
            response_serializer=lambda x: x,
        ),
    }

    handler = grpc.ServiceRpcHandlers(service_name, rpc_method_handlers)
    server.add_generic_rpc_handlers((handler,))
