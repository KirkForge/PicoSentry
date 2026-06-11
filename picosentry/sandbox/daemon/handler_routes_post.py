from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from importlib import import_module
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from picosentry.sandbox.audit import AuditEventType, get_audit_logger
from picosentry.sandbox.daemon.constants import _ENTERPRISE_MODE
from picosentry.sandbox.errors import ErrorCodes
from picosentry.sandbox.l3.backends.base import SandboxBackend
from picosentry.sandbox.l3.engine import sandbox_run
from picosentry.sandbox.l3.policy import default_policy, load_policy
from picosentry.sandbox.l4.engine import create_default_engine
from picosentry.sandbox.l4.profiler import profile_from_sandbox_result
from picosentry.sandbox.retention import get_retention_manager

if TYPE_CHECKING:
    from picosentry.sandbox.daemon.handler import PicoDomeHandler

logger = logging.getLogger("picodome.daemon")


class PicoDomePostRoutesMixin:

    def _handle_post(self: PicoDomeHandler) -> None:

        content_length = self.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > self.MAX_REQUEST_SIZE:
                    self._send_error(ErrorCodes.REQUEST_TOO_LARGE)
                    return
            except (ValueError, OverflowError):
                self._send_error(400, "Invalid Content-Length")
                return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == f"/api/{self.API_VERSION}/scan":
            token = self._require_permission("scan:submit")
            if token:
                self._handle_submit_scan(token)
        elif path == f"/api/{self.API_VERSION}/policies":
            token = self._require_permission("policy:write")
            if token:
                self._handle_create_policy(token)
        else:
            self._send_error(ErrorCodes.NOT_FOUND, detail=path)

    def _handle_submit_scan(self: PicoDomeHandler, token: str) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > self.MAX_REQUEST_SIZE:
                self._send_error(ErrorCodes.REQUEST_TOO_LARGE)
                return

            content_type = self.headers.get("Content-Type", "")
            if content_type and "application/json" not in content_type:
                self._send_error(ErrorCodes.INVALID_JSON, detail=f"Expected application/json, got {content_type}")
                return
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError) as e:
            self._send_error(ErrorCodes.INVALID_JSON, detail=str(e))
            return

        command = data.get("command")
        if not command or not isinstance(command, list):
            self._send_error(ErrorCodes.MISSING_COMMAND)
            return


        deny_error = self._validate_command(command)
        if deny_error:

            actor = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16] if token else "unknown"
            try:
                audit = get_audit_logger()
                audit.record(
                    event_type=AuditEventType.COMMAND_DENIED,
                    actor=actor,
                    detail=deny_error,
                    target=command[0] if command else "",
                    metadata={"command": command},
                )
            except Exception:
                pass
            self._send_error(ErrorCodes.COMMAND_DENIED, detail=deny_error)
            return

        timeout = data.get("timeout", 30.0)
        data.get("policy")

        job_id = uuid.uuid4().hex
        actor = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16] if token else "unknown"


        tenant_id = self._resolve_tenant(token)

        self.job_store.add(job_id, command, actor)


        try:
            audit = get_audit_logger()
            audit.record(
                event_type=AuditEventType.SCAN_START,
                actor=actor,
                detail=f"{' '.join(command)}",
                target=command[0] if command else "",
                metadata={"job_id": job_id, "timeout": timeout, "tenant_id": str(tenant_id)},
            )
        except Exception:
            pass

        try:

            policy_name = data.get("policy")
            if policy_name:
                try:
                    policy = load_policy(name=policy_name)
                except Exception:
                    logger.warning("Policy '%s' not found, using default", policy_name)
                    policy = default_policy()
            else:
                policy = default_policy()


            backend_name = data.get("backend", "auto")
            backend: SandboxBackend | None = None

            if _ENTERPRISE_MODE and backend_name == "subprocess":
                self._send_error(ErrorCodes.ENTERPRISE_ENFORCEMENT, detail="subprocess backend is not allowed in enterprise mode")
                return
            if backend_name != "auto":
                backend_map = {
                    "subprocess": "picodome.l3.backends.subprocess_backend:SubprocessBackend",
                    "seccomp-bpf": "picodome.l3.backends.seccomp_backend:SeccompBackend",
                    "seatbelt": "picodome.l3.backends.seatbelt_backend:SeatbeltBackend",
                }
                cls_path = backend_map.get(backend_name)
                if cls_path is None:
                    self._send_error(ErrorCodes.INVALID_BACKEND, detail=backend_name)
                    return
                try:
                    module_path, cls_name = cls_path.rsplit(":", 1)

                    backend_cls = getattr(import_module(module_path), cls_name)
                    backend = backend_cls()
                    if not backend.is_available():
                        self._send_error(ErrorCodes.BACKEND_UNAVAILABLE, detail=backend_name)
                        return
                except Exception as e:
                    self._send_error(ErrorCodes.BACKEND_UNAVAILABLE, detail=str(e))
                    return


            sandbox_result = sandbox_run(
                command=command,
                policy=policy,
                timeout=timeout,
                backend=backend,
                deterministic=False,
            )


            engine = create_default_engine()
            profile = profile_from_sandbox_result(sandbox_result)
            analysis_result = engine.analyze(profile, deterministic=False)


            result = {
                "job_id": job_id,
                "sandbox": sandbox_result.to_dict(deterministic=False),
                "analysis": analysis_result.to_dict(deterministic=False),
                "l3_verdict": sandbox_result.overall_verdict.value,
                "l4_verdict": analysis_result.overall_verdict.value,
                "findings_count": len(analysis_result.findings),
                "backend": sandbox_result.backend_name,
                "isolation_level": sandbox_result.isolation_level,
                "enforcement_guarantee": sandbox_result.enforcement_guarantee,
                "degraded": sandbox_result.degraded,
                "policy_name": policy.name,
                "policy_version": policy.version,
            }

            self.job_store.update(
                job_id,
                status="completed",
                completed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                result=result,
            )


            self._scan_count += 1
            self._scan_total_ms += sandbox_result.duration_ms
            self._alert_count += len(analysis_result.findings)


            try:
                audit = get_audit_logger()
                audit.record(
                    event_type=AuditEventType.SCAN_COMPLETE,
                    actor=actor,
                    detail=f"l3={sandbox_result.overall_verdict.value} l4={analysis_result.overall_verdict.value}",
                    target=command[0] if command else "",
                    metadata={"job_id": job_id, "findings": len(analysis_result.findings)},
                )
            except Exception:
                pass


            try:
                rm = get_retention_manager()
                rm.save_scan_result(
                    json.dumps(result, sort_keys=True, default=str),
                    package_name=command[0] if command else "unknown",
                )
            except Exception:
                pass

            self._send_json(result, status=201)

        except Exception as e:
            self.job_store.update(
                job_id,
                status="failed",
                completed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                error=str(e),
            )
            logger.exception("Scan job %s failed", job_id)
            self._send_error(ErrorCodes.SCAN_FAILED, detail=str(e))

    def _handle_create_policy(self: PicoDomeHandler, token: str) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            content_type = self.headers.get("Content-Type", "")
            if content_type and "application/json" not in content_type:
                self._send_error(ErrorCodes.INVALID_JSON, detail=f"Expected application/json, got {content_type}")
                return
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError) as e:
            self._send_error(ErrorCodes.INVALID_JSON, detail=str(e))
            return

        from picosentry.sandbox.l3.policy import _policy_from_dict
        from picosentry.sandbox.policy_versioned import get_policy_store

        try:
            policy = _policy_from_dict(data)
            store = get_policy_store()
            author = data.get("author", hashlib.sha256(token.encode("utf-8")).hexdigest()[:16] if token else "unknown")
            description = data.get("change_description", "")
            pv = store.save(policy, author=author, change_description=description)
            self._send_json(pv.to_dict(), status=201)
        except Exception as e:
            self._send_error(ErrorCodes.INVALID_POLICY, detail=str(e))


__all__ = ["PicoDomePostRoutesMixin"]
