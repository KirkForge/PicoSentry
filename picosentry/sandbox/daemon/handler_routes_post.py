from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
import time
import uuid
from importlib import import_module
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from picosentry.sandbox.audit import AuditEventType, get_audit_logger
from picosentry.sandbox.daemon.constants import _ENTERPRISE_MODE, sanitize_scan_timeout
from picosentry.sandbox.daemon.handler_routes_get import _check_cluster_token
from picosentry.sandbox.errors import ErrorCodes
from picosentry.sandbox.l3.engine import sandbox_run
from picosentry.sandbox.l3.policy import default_policy, load_policy
from picosentry.sandbox.policy_versioned.signing import (
    load_key,
    sign_policy_companion,
)
from picosentry.sandbox.l4.engine import create_default_engine
from picosentry.sandbox.l4.profiler import profile_from_sandbox_result
from picosentry.sandbox.retention import get_retention_manager

if TYPE_CHECKING:
    from picosentry.sandbox.l3.backends.base import SandboxBackend
    from picosentry.sandbox.daemon.handler import PicoDomeHandler

logger = logging.getLogger("picodome.daemon")

# _check_cluster_token lives in handler_routes_get (WO5.0.0-018: it was
# duplicated verbatim here with drifted exception tuples).


def _max_scan_timeout_seconds() -> float:
    """Upper bound for scan timeout from env (default 300 s). Shared with the gRPC transport."""
    from picosentry.sandbox.daemon.constants import max_scan_timeout_seconds

    return max_scan_timeout_seconds()


# Maps daemon API ``backend`` values to the fully-qualified backend class.
# This is a single source of truth so tests can verify the paths stay valid
# and the typo that once used the old ``picodome`` namespace cannot recur.
_DAEMON_BACKEND_MAP: dict[str, str] = {
    "subprocess": "picosentry.sandbox.l3.backends.subprocess_backend:SubprocessBackend",
    "seccomp-bpf": "picosentry.sandbox.l3.backends.seccomp_backend:SeccompBackend",
    "seatbelt": "picosentry.sandbox.l3.backends.seatbelt_backend:SeatbeltBackend",
}


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
        elif path == f"/api/{self.API_VERSION}/cluster/snapshot":
            # Cluster peers authenticate with X-Cluster-Token only (WO5.0.0-004).
            from picosentry.sandbox.daemon.handler_routes_get import _authorize_cluster_route

            if _authorize_cluster_route(self, "scan:write"):
                self._handle_cluster_merge_snapshot()
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
        except (json.JSONDecodeError, ValueError):
            self._send_error(ErrorCodes.INVALID_JSON, detail="Invalid JSON")
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
            except (OSError, RuntimeError):
                logger.exception("Audit record failed")
            self._send_error(ErrorCodes.COMMAND_DENIED, detail=deny_error)
            return

        timeout = sanitize_scan_timeout(data.get("timeout", 30.0))
        if timeout is None:
            self._send_error(ErrorCodes.INVALID_TIMEOUT, detail="timeout must be a finite number")
            return

        # WO5.0.0-017: validate policy and backend BEFORE persisting the job.
        # The old add-first order error-returned on every validation failure
        # without failing the row, leaving orphaned pending jobs forever.
        policy_name = data.get("policy")
        if policy_name:
            try:
                policy = load_policy(name=policy_name, verify_signature=True)
            except FileNotFoundError:
                logger.warning("Policy '%s' not found", policy_name)
                self._send_error(ErrorCodes.INVALID_POLICY, detail=f"policy '{policy_name}' not found")
                return
            except ValueError as exc:
                logger.warning("Policy '%s' could not be loaded: %s", policy_name, exc)
                self._send_error(ErrorCodes.INVALID_POLICY, detail="policy signature verification failed")
                return
        else:
            policy = default_policy()

        backend_name = data.get("backend", "auto")
        backend: SandboxBackend | None = None

        if _ENTERPRISE_MODE and backend_name == "subprocess":
            self._send_error(
                ErrorCodes.ENTERPRISE_ENFORCEMENT,
                detail="subprocess backend is not allowed in enterprise mode",
            )
            return
        if backend_name != "auto":
            cls_path = _DAEMON_BACKEND_MAP.get(backend_name)
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
            except (ImportError, AttributeError, ValueError, RuntimeError):
                logger.exception("Backend instantiation failed for %s", backend_name)
                self._send_error(ErrorCodes.BACKEND_UNAVAILABLE, detail=backend_name)
                return

        job_id = uuid.uuid4().hex
        actor = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16] if token else "unknown"

        tenant_id = self._resolve_tenant(token)

        # Tenant-scoped add (WO4.0.0-010): the job is persisted with its
        # owning tenant so later reads are denied cross-tenant. A store that
        # cannot persist rejects the submit — never a fake 201 (WO5.0.0-017).
        try:
            self.job_store.add(job_id, command, actor, tenant_id=tenant_id)
        except (OSError, RuntimeError) as exc:
            logger.error("Job store unavailable, rejecting submit of %s: %s", job_id, exc)
            self._send_error(ErrorCodes.NOT_READY, detail="job store unavailable")
            return

        try:
            audit = get_audit_logger()
            audit.record(
                event_type=AuditEventType.SCAN_START,
                actor=actor,
                detail=f"{' '.join(command)}",
                target=command[0] if command else "",
                metadata={"job_id": job_id, "timeout": timeout, "tenant_id": str(tenant_id)},
            )
        except (OSError, RuntimeError):
            logger.exception("Audit record failed")

        try:
            executor = self.scan_executor
            if executor is None:
                # No daemon-managed pool (direct handler use): run inline.
                try:
                    result = self._run_scan_job(
                        job_id, command, policy, timeout, backend, actor, tenant_id, release_slot=False
                    )
                    self._send_json(result, status=201)
                except (OSError, RuntimeError):
                    self._send_error(ErrorCodes.SCAN_FAILED, detail="scan execution failed")
                return

            if self.scan_slots is not None and not self.scan_slots.acquire(blocking=False):
                self.job_store.update(
                    job_id,
                    tenant_id=tenant_id,
                    status="failed",
                    completed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    error="scan queue full",
                )
                logger.warning("Scan queue full — rejecting job %s", job_id)
                self._send_error(ErrorCodes.RATE_LIMITED, detail="scan queue full")
                return

            self.job_store.update(job_id, tenant_id=tenant_id, status="queued")
            try:
                future = executor.submit(
                    self._run_scan_job, job_id, command, policy, timeout, backend, actor, tenant_id
                )
            except RuntimeError:
                # Executor already shut down (daemon stopping, or a stale
                # executor reference) — run inline rather than fail the scan.
                logger.warning("Scan executor unavailable — running job %s inline", job_id)
                try:
                    try:
                        result = self._run_scan_job(
                            job_id, command, policy, timeout, backend, actor, tenant_id, release_slot=False
                        )
                    finally:
                        if self.scan_slots is not None:
                            self.scan_slots.release()
                    self._send_json(result, status=201)
                except (OSError, RuntimeError):
                    self._send_error(ErrorCodes.SCAN_FAILED, detail="scan execution failed")
                return
            try:
                result = future.result()
            except concurrent.futures.CancelledError:
                self._send_error(ErrorCodes.NOT_READY, detail="scan cancelled during shutdown")
            except (OSError, RuntimeError):
                logger.exception("Scan job failed")
                self._send_error(ErrorCodes.SCAN_FAILED, detail="scan execution failed")
            else:
                self._send_json(result, status=201)
        except (OSError, RuntimeError):
            self.job_store.update(
                job_id,
                tenant_id=tenant_id,
                status="failed",
                completed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                error="scan execution failed",
            )
            logger.exception("Scan job failed")
            self._send_error(ErrorCodes.SCAN_FAILED, detail="scan execution failed")

    def _run_scan_job(
        self: PicoDomeHandler,
        job_id: str,
        command: list[str],
        policy: Any,
        timeout: float,
        backend: SandboxBackend | None,
        actor: str,
        tenant_id: Any = None,
        release_slot: bool = True,
    ) -> dict[str, Any]:
        """Execute one scan; runs on a worker thread when the daemon pool is active.

        Job store transitions: queued → running → completed/failed.
        """
        try:
            self.job_store.update(job_id, tenant_id=tenant_id, status="running")

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

            from picosentry.sandbox.daemon.redaction import redact_sandbox_output

            # getattr: embedded/test result objects may not carry events.
            sandbox_dict = redact_sandbox_output(
                sandbox_result.to_dict(deterministic=False), getattr(sandbox_result, "events", [])
            )

            result = {
                "job_id": job_id,
                "sandbox": sandbox_dict,
                "analysis": analysis_result.to_dict(deterministic=False),
                "l3_verdict": sandbox_result.overall_verdict.value,
                "l4_verdict": analysis_result.overall_verdict.value,
                "findings_count": len(analysis_result.findings),
                "backend": sandbox_result.backend_name,
                "isolation_level": sandbox_result.isolation_level,
                "enforcement_guarantee": sandbox_result.enforcement_guarantee,
                "degraded": sandbox_result.degraded,
                "output_redacted": bool(sandbox_dict.get("stdout_redacted") or sandbox_dict.get("stderr_redacted")),
                "policy_name": policy.name,
                "policy_version": policy.version,
            }

            self.job_store.update(
                job_id,
                tenant_id=tenant_id,
                status="completed",
                completed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                result=result,
            )

            with self._stats_lock:
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
                    metadata={
                        "job_id": job_id,
                        "findings": len(analysis_result.findings),
                        "tenant_id": str(tenant_id) if tenant_id is not None else None,
                    },
                )
            except (OSError, RuntimeError):
                logger.exception("Audit record failed")

            try:
                rm = get_retention_manager()
                rm.save_scan_result(
                    json.dumps(result, sort_keys=True, default=str),
                    package_name=command[0] if command else "unknown",
                )
            except (OSError, ValueError, TypeError):
                logger.exception("Retention save failed")

            return result
        except BaseException:
            self.job_store.update(
                job_id,
                tenant_id=tenant_id,
                status="failed",
                completed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                error="scan execution failed",
            )
            raise
        finally:
            if release_slot and self.scan_slots is not None:
                self.scan_slots.release()

    def _handle_create_policy(self: PicoDomeHandler, token: str) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            content_type = self.headers.get("Content-Type", "")
            if content_type and "application/json" not in content_type:
                self._send_error(ErrorCodes.INVALID_JSON, detail=f"Expected application/json, got {content_type}")
                return
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            self._send_error(ErrorCodes.INVALID_JSON, detail="Invalid JSON")
            return

        from picosentry.sandbox.l3.policy import _policy_from_dict
        from picosentry.sandbox.policy_versioned import get_policy_store

        try:
            policy = _policy_from_dict(data)
            store = get_policy_store()
            author = data.get("author", hashlib.sha256(token.encode("utf-8")).hexdigest()[:16] if token else "unknown")
            description = data.get("change_description", "")
            pv = store.save(policy, author=author, change_description=description)
            key = load_key()
            if key is not None:
                latest_path = store._store_dir / policy.name / "latest.json"
                try:
                    sign_policy_companion(latest_path, key)
                except OSError:
                    logger.exception("Failed to sign policy companion for %s", policy.name)
            self._send_json(pv.to_dict(), status=201)
        except (ValueError, KeyError, TypeError):
            self._send_error(ErrorCodes.INVALID_POLICY, detail="Invalid policy data")
        except (OSError, RuntimeError):
            logger.exception("Policy creation failed")
            self._send_error(ErrorCodes.INVALID_POLICY, detail="policy creation failed")

    def _handle_cluster_merge_snapshot(self: PicoDomeHandler) -> None:
        """POST /api/v1/cluster/snapshot — merge a peer's cluster state.

        Accepts a pushed snapshot authenticated by X-Cluster-Token (the same
        token the gossip client uses for GET). The daemon's own gossip loop
        pulls snapshots via GET and merges locally, so this endpoint serves
        peers/operators that push instead of pull.
        Body must be a JSON snapshot as produced by GET /api/v1/cluster/snapshot.
        Merging follows last-writer-wins for nodes and status-priority for scans.
        """
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > self.MAX_REQUEST_SIZE:
                self._send_error(ErrorCodes.REQUEST_TOO_LARGE)
                return

            body = self.rfile.read(content_length)
            snapshot = json.loads(body)

            if not isinstance(snapshot, dict):
                self._send_error(400, "snapshot must be a JSON object")
                return

            from picosentry.sandbox.cluster.manager import get_cluster_manager

            mgr = get_cluster_manager()
            if not mgr.is_running:
                self._send_error(409, "cluster manager is not running on this node")
                return

            if not _check_cluster_token(self, mgr):
                return

            before_nodes = len(mgr.state.list_nodes())
            mgr.state.merge_state(snapshot)
            after_nodes = len(mgr.state.list_nodes())

            audit = get_audit_logger()
            audit.record(
                event_type=AuditEventType.CLUSTER_GOSSIP,
                actor="cluster-gossip",
                detail=f"Merged peer snapshot: {before_nodes}→{after_nodes} nodes",
            )

            self._send_json(
                {
                    "status": "merged",
                    "nodes_before": before_nodes,
                    "nodes_after": after_nodes,
                    "leader_id": mgr.state.get_leader_id(),
                }
            )
        except json.JSONDecodeError:
            self._send_error(400, "invalid JSON body")
        except (OSError, RuntimeError, ValueError, TypeError):
            logger.exception("Cluster snapshot merge failed")
            self._send_error(500, "cluster merge failed")


__all__ = ["PicoDomePostRoutesMixin"]
