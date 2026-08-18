from __future__ import annotations

import contextlib
import json
import logging
import time
import uuid
from typing import Any

from picosentry.sandbox import __version__

logger = logging.getLogger("picodome.grpc_transport.servicer")


class PicoDomeServicer:
    def __init__(self, scan_engine, start_time: float, scan_count_ref: Any, auth: Any | None = None) -> None:
        self._scan_engine = scan_engine
        self._start_time = start_time
        self._scan_count_ref = scan_count_ref
        self._auth = auth

    def Scan(self, request, context):
        self._audit_log("SCAN_START", detail=f"command={list(request.command)}")

        try:
            command = list(request.command) if hasattr(request, "command") else []

            # Same command policy as the HTTP daemon (WO4.0.0-002).
            from picosentry.sandbox.daemon.constants import validate_command

            deny_error = validate_command(command)
            if deny_error:
                self._audit_log("SCAN_ERROR", detail=deny_error)
                return self._reject(context, "PERMISSION_DENIED", deny_error)

            policy_name = request.policy if hasattr(request, "policy") else ""
            raw_timeout = request.timeout if hasattr(request, "timeout") and request.timeout else 30.0
            from picosentry.sandbox.daemon.constants import sanitize_scan_timeout

            timeout = sanitize_scan_timeout(raw_timeout)
            if timeout is None:
                self._audit_log("SCAN_ERROR", detail=f"invalid timeout: {raw_timeout!r}")
                return self._reject(context, "INVALID_ARGUMENT", "timeout must be a finite number")

            cwd = request.cwd if hasattr(request, "cwd") and request.cwd else None
            if cwd:
                from picosentry.sandbox.daemon.constants import confine_cwd

                confined = confine_cwd(cwd)
                if confined is None:
                    self._audit_log("SCAN_ERROR", detail=f"cwd outside workspace root: {cwd}")
                    return self._reject(context, "PERMISSION_DENIED", "cwd escapes workspace root")
                cwd = str(confined)

            policy = None
            if policy_name:
                try:
                    from picosentry.sandbox.l3.policy import load_policy

                    policy = load_policy(name=policy_name, verify_signature=True)
                except FileNotFoundError:
                    return self._reject(context, "NOT_FOUND", f"policy '{policy_name}' not found")
                except (OSError, RuntimeError, ValueError, TypeError, ImportError) as e:
                    logger.warning("Policy '%s' rejected: %s", policy_name, e)
                    return self._reject(context, "INVALID_ARGUMENT", f"invalid policy '{policy_name}'")

            from picosentry.sandbox.tenant import TenantMismatchError

            try:
                tenant_id = self._resolve_tenant(context)
            except TenantMismatchError:
                self._audit_log("SCAN_ERROR", detail="x-tenant does not match token's tenant")
                return self._reject(context, "PERMISSION_DENIED", "x-tenant does not match token's tenant")

            sandbox_result = self._scan_engine.scan(
                command=command,
                policy=policy,
                timeout=timeout,
                cwd=cwd,
                deterministic=False,
            )

            analysis_result = self._scan_engine.analyze(
                sandbox_result,
                deterministic=False,
            )

            result = {
                "job_id": f"grpc-{uuid.uuid4().hex}",
                "sandbox": sandbox_result.to_dict(deterministic=False),
                "analysis": analysis_result.to_dict(deterministic=False),
                "l3_verdict": sandbox_result.overall_verdict.value,
                "l4_verdict": analysis_result.overall_verdict.value,
                "findings_count": len(analysis_result.findings),
            }

            if hasattr(self._scan_count_ref, "_scan_count"):
                self._scan_count_ref._scan_count += 1

            self._audit_log(
                "SCAN_COMPLETE",
                detail=f"l3={sandbox_result.overall_verdict.value} l4={analysis_result.overall_verdict.value}"
                f" tenant={tenant_id}",
            )

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
            if not getattr(context, "is_active", lambda: True)():
                # context.abort() already terminated this RPC — propagate, don't
                # log it as a scan failure.
                raise
            logger.exception("Scan RPC failed")
            self._audit_log("SCAN_ERROR", detail=type(e).__name__)

            error_result = {
                "result_json": json.dumps({"error": "scan_failed"}),
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
                return _DictProxy(error_result)

    def Health(self, request, context):
        uptime = int(time.time() - self._start_time)

        try:
            from picosentry.sandbox.health import check_health

            checks = check_health()
            all_healthy = all(c.healthy for c in checks)
        except (OSError, RuntimeError, ValueError, TypeError, ImportError):
            logger.debug("Health check failed, defaulting to healthy", exc_info=True)
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
        name = request.name if hasattr(request, "name") else ""
        if name and ("/" in name or "\\" in name or ".." in name):
            return self._reject(context, "INVALID_ARGUMENT", f"Invalid policy name: {name!r}")

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
        except (OSError, RuntimeError, ValueError, TypeError, ImportError) as e:
            logger.warning("GetPolicy failed for %s: %s", name, e)
            policy_json = json.dumps({"error": "policy lookup failed"})
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
                with contextlib.suppress(ValueError):
                    et = AuditEventType(event_type)

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
        except (OSError, ImportError):
            logger.exception("Audit query failed")
            events_json = json.dumps({"error": "audit_query_failed"})
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

    def _reject(self, context, code_name: str, detail: str):
        """Abort the RPC with a gRPC status code. Real contexts raise on abort."""
        import grpc

        code = {
            "UNAUTHENTICATED": grpc.StatusCode.UNAUTHENTICATED,
            "PERMISSION_DENIED": grpc.StatusCode.PERMISSION_DENIED,
            "INVALID_ARGUMENT": grpc.StatusCode.INVALID_ARGUMENT,
            "NOT_FOUND": grpc.StatusCode.NOT_FOUND,
        }.get(code_name, grpc.StatusCode.INVALID_ARGUMENT)
        context.abort(code, detail)
        return

    def _resolve_tenant(self, context) -> str:
        """Tenant resolution mirroring the HTTP daemon's rule (WO5.0.0-001):
        the x-tenant metadata key may only confirm the token's mapped tenant;
        anything else raises TenantMismatchError (the caller rejects the RPC)."""
        from picosentry.sandbox.tenant import TenantMismatchError, get_tenant_registry

        try:
            from picosentry.sandbox.grpc_transport.auth import bearer_token_from_metadata, metadata_value

            token = bearer_token_from_metadata(context.invocation_metadata())
            header_tenant = metadata_value(context.invocation_metadata(), "x-tenant") or None
            import hashlib

            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest() if token else ""
            return str(get_tenant_registry().resolve_tenant(token_hash, header_tenant=header_tenant))
        except TenantMismatchError:
            raise
        except Exception:
            logger.debug("tenant resolution failed", exc_info=True)
            return ""

    def _audit_log(self, event_type: str, detail: str = "") -> None:
        try:
            from picosentry.sandbox.audit import AuditEventType, get_audit_logger

            audit = get_audit_logger()

            try:
                et = AuditEventType(event_type)
            except ValueError:
                et = AuditEventType.SCAN_START  # fallback
            audit.record(
                event_type=et,
                actor="picodome-grpc",
                detail=detail,
            )
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
            logger.debug("Audit log failed for event %s", event_type, exc_info=True)


class _DictProxy:
    def __init__(self, data: dict) -> None:
        self._data = data

    def __getattr__(self, name: str):
        if name.startswith("_"):
            return super().__getattribute__(name)
        return self._data.get(name, "")

    def __repr__(self) -> str:
        return f"_DictProxy({self._data})"


def add_servicer_manually(servicer, server):
    """Fallback servicer registration when the generated pb2_grpc
    stubs are unavailable (e.g. the grpcio version on the target host
    doesn't match the version the stubs were generated against, or
    someone deleted the stubs out from under the install).

    The modern grpcio API replaced ``grpc.ServiceRpcHandlers`` (which
    was removed) with ``grpc.method_handlers_generic_handler``.  This
    function uses the modern API so the fallback is actually live.

    Note: identity passthrough deserializers/serializers mean callers
    send raw protobuf bytes, not dicts.  The generated stubs use the
    real protobuf codecs — prefer the stub path when available.
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

    handler = grpc.method_handlers_generic_handler(service_name, rpc_method_handlers)
    server.add_generic_rpc_handlers((handler,))
