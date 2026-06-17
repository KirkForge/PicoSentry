from __future__ import annotations

import contextlib
import hashlib
import logging
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

from picosentry.sandbox import __version__
from picosentry.sandbox.audit import AuditEventType, get_audit_logger
from picosentry.sandbox.daemon.constants import _ENTERPRISE_MODE
from picosentry.sandbox.errors import ErrorCodes
from picosentry.sandbox.retention import get_retention_manager

if TYPE_CHECKING:
    from picosentry.sandbox.daemon.handler import PicoDomeHandler

logger = logging.getLogger("picodome.daemon")


def _check_cluster_token(self: PicoDomeHandler, mgr: Any) -> bool:
    """Verify X-Cluster-Token header matches the configured cluster token."""
    expected = mgr.state.cluster_token
    if not expected:
        return True
    provided = self.headers.get("X-Cluster-Token", "")
    if provided != expected:
        actor = hashlib.sha256(provided.encode("utf-8")).hexdigest()[:16] if provided else "anonymous"
        try:
            audit = get_audit_logger()
            audit.record(
                event_type=AuditEventType.AUTH_FAILURE,
                actor=actor,
                detail="Cluster token mismatch",
                target=self.path,
            )
        except Exception:
            pass
        self._send_error(403, "cluster token mismatch")
        return False
    return True


class PicoDomeGetRoutesMixin:

    def _handle_get(self: PicoDomeHandler) -> None:

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
        query = parse_qs(parsed.query)


        if path == "/health":

            if not self.rate_limiter.allow(actor="__health__"):
                self._send_error(ErrorCodes.RATE_LIMITED)
            else:
                self._handle_health()
        elif path == "/ready":
            if not self.rate_limiter.allow(actor="__ready__"):
                self._send_error(ErrorCodes.RATE_LIMITED)
            else:
                self._handle_ready()
        elif path == "/metrics":

            metrics_only = getattr(self, "_metrics_only", False)
            if metrics_only:
                self._handle_metrics()
            else:
                token = self._require_permission("scan:read")
                if token:
                    self._handle_metrics()


        elif path == f"/api/{self.API_VERSION}/scans":
            token = self._require_permission("scan:read")
            if token:
                self._handle_list_scans(query)
        elif path.startswith(f"/api/{self.API_VERSION}/scan/"):
            token = self._require_permission("scan:read")
            if token:
                job_id = path.split("/")[-1]
                self._handle_get_scan(job_id)
        elif path == f"/api/{self.API_VERSION}/policies":
            token = self._require_permission("policy:read")
            if token:
                self._handle_list_policies()
        elif path.startswith(f"/api/{self.API_VERSION}/policies/"):
            token = self._require_permission("policy:read")
            if token:
                name = path.split("/")[-1]
                self._handle_get_policy(name)
        elif path == f"/api/{self.API_VERSION}/baselines":
            token = self._require_permission("baseline:read")
            if token:
                self._handle_list_baselines()
        elif path == f"/api/{self.API_VERSION}/audit":
            token = self._require_permission("audit:read")
            if token:
                self._handle_audit_query(query)
        elif path == f"/api/{self.API_VERSION}/tenants":
            token = self._require_permission("audit:read")
            if token:
                self._handle_list_tenants()
        elif path == f"/api/{self.API_VERSION}/tls/config":
            token = self._require_permission("scan:read")
            if token:
                self._handle_tls_config()
        elif path == f"/api/{self.API_VERSION}/stats":
            token = self._require_permission("scan:read")
            if token:
                self._handle_stats()
        elif path == f"/api/{self.API_VERSION}/cluster/snapshot":
            token = self._require_permission("scan:read")
            if token:
                self._handle_cluster_snapshot()
        else:
            self._send_error(ErrorCodes.NOT_FOUND, detail=path)

    def _handle_health(self: PicoDomeHandler) -> None:
        uptime = int(time.time() - self._start_time)


        redis_health = {}
        try:
            from picosentry.sandbox.redis_health import check_redis_health

            redis_health = check_redis_health()
        except Exception:
            redis_health = {"connected": False, "mode": "in-memory"}


        health_data: dict[str, Any] = {
            "status": "healthy",
        }

        if not _ENTERPRISE_MODE:
            health_data["version"] = __version__
            health_data["api_version"] = self.API_VERSION
            health_data["uptime_seconds"] = uptime
            health_data["redis"] = redis_health

        self._send_json(health_data)

    def _handle_ready(self: PicoDomeHandler) -> None:


        try:
            from picosentry.sandbox.l3.engine import _detect_backend

            enterprise_mode = _ENTERPRISE_MODE
            backend = _detect_backend(allow_degraded=not enterprise_mode)
            is_degraded = backend.isolation_level == "observational_only"

            if enterprise_mode and backend.isolation_level == "observational_only":
                self._send_error(
                    ErrorCodes.ENTERPRISE_ENFORCEMENT,
                    detail=f"Only '{backend.name}' backend available — install libseccomp2 (Linux) or use macOS",
                )
                return

            response = {
                "status": "ready",
                "backend": backend.name,
                "isolation_level": backend.isolation_level,
                "enforcement_guarantee": backend.enforcement_guarantee,
            }  # type: dict[str, object]
            if is_degraded:
                response["degraded"] = True
                response["warning"] = "Running in observational-only mode — no real syscall enforcement"
            self._send_json(response)
        except Exception as e:
            self._send_error(ErrorCodes.NOT_READY, detail=str(e))

    def _handle_metrics(self: PicoDomeHandler) -> None:
        uptime = int(time.time() - self._start_time)
        avg_ms = self._scan_total_ms / max(self._scan_count, 1)

        lines = [
            "# HELP picodome_scans_total Total number of scans executed",
            "# TYPE picodome_scans_total counter",
            f"picodome_scans_total {self._scan_count}",
            "",
            "# HELP picodome_scan_duration_ms_avg Average scan duration in ms",
            "# TYPE picodome_scan_duration_ms_avg gauge",
            f"picodome_scan_duration_ms_avg {avg_ms}",
            "",
            "# HELP picodome_alerts_total Total number of alerts generated",
            "# TYPE picodome_alerts_total counter",
            f"picodome_alerts_total {self._alert_count}",
            "",
            "# HELP picodome_uptime_seconds Daemon uptime in seconds",
            "# TYPE picodome_uptime_seconds gauge",
            f"picodome_uptime_seconds {uptime}",
            "",
            "# HELP picodome_version PicoDome version info",
            "# TYPE picodome_version gauge",
            f'picodome_version{{version="{__version__}"}} 1',
        ]

        body = "\n".join(lines).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_get_scan(self: PicoDomeHandler, job_id: str) -> None:
        job = self.job_store.get(job_id)
        if job:
            self._send_json(job)
        else:
            self._send_error(ErrorCodes.SCAN_NOT_FOUND, detail=job_id)

    def _handle_list_scans(self: PicoDomeHandler, query: dict) -> None:
        limit = int(query.get("limit", ["50"])[0])
        jobs = self.job_store.list_recent(limit=limit)
        self._send_json(
            {
                "scans": jobs,
                "count": len(jobs),
            }
        )

    def _handle_list_policies(self: PicoDomeHandler) -> None:
        from picosentry.sandbox.policy_versioned import get_policy_store

        store = get_policy_store()
        names = store.list_policies()
        self._send_json({"policies": names, "count": len(names)})

    def _handle_get_policy(self: PicoDomeHandler, name: str) -> None:
        from picosentry.sandbox.policy_versioned import get_policy_store

        store = get_policy_store()
        pv = store.load(name)
        if pv:
            self._send_json(pv.to_dict())
        else:
            self._send_error(ErrorCodes.POLICY_NOT_FOUND, detail=name)

    def _handle_list_baselines(self: PicoDomeHandler) -> None:
        from picosentry.sandbox.l4.baseline import load_all_baselines

        baselines = load_all_baselines()
        self._send_json(
            {
                "baselines": {k: v.to_dict() for k, v in baselines.items()},
                "count": len(baselines),
            }
        )

    def _handle_audit_query(self: PicoDomeHandler, query: dict) -> None:
        from picosentry.sandbox.audit import AuditEventType, get_audit_logger

        audit = get_audit_logger()

        event_type = None
        if "event_type" in query:
            with contextlib.suppress(ValueError):
                event_type = AuditEventType(query["event_type"][0])

        events = audit.query(
            event_type=event_type,
            actor=query.get("actor", [None])[0],
            target=query.get("target", [None])[0],
            since=query.get("since", [None])[0],
            until=query.get("until", [None])[0],
            limit=int(query.get("limit", ["100"])[0]),
        )
        self._send_json(
            {
                "events": [e.to_dict() for e in events],
                "count": len(events),
            }
        )

    def _handle_list_tenants(self: PicoDomeHandler) -> None:
        from picosentry.sandbox.tenant import get_tenant_registry

        registry = get_tenant_registry()
        tenants = registry.list_tenants()
        self._send_json(
            {
                "tenants": [
                    {
                        "tenant_id": str(ctx.tenant_id),
                        "display_name": ctx.display_name,
                        "is_default": ctx.is_default,
                    }
                    for ctx in tenants
                ],
                "count": len(tenants),
            }
        )

    def _handle_tls_config(self: PicoDomeHandler) -> None:
        from picosentry.sandbox.mtls import get_tls_config_info

        config_info = get_tls_config_info()
        self._send_json(config_info)

    def _handle_stats(self: PicoDomeHandler) -> None:
        rm = get_retention_manager()
        storage = rm.get_storage_stats()
        audit = get_audit_logger()
        audit_stats = audit.get_stats()


        stats_data: dict[str, Any] = {
            "scans_total": self._scan_count,
            "scans_avg_ms": self._scan_total_ms / max(self._scan_count, 1),
            "alerts_total": self._alert_count,
        }
        if not _ENTERPRISE_MODE:
            stats_data["version"] = __version__
            stats_data["uptime_seconds"] = int(time.time() - self._start_time)
            stats_data["storage"] = storage
            stats_data["audit"] = audit_stats

        self._send_json(stats_data)

    def _handle_cluster_snapshot(self: PicoDomeHandler) -> None:
        """GET /api/v1/cluster/snapshot — return full cluster state for gossip.

        Cluster nodes call this endpoint on their peers to discover nodes,
        scan assignments, and the current leader.  The caller merges the
        returned snapshot via POST /api/v1/cluster/snapshot.
        """
        try:
            from picosentry.sandbox.cluster.manager import get_cluster_manager

            mgr = get_cluster_manager()
            if not mgr.is_running:
                self._send_json({
                    "cluster": "inactive",
                    "detail": "Cluster manager is not running on this node",
                })
                return

            if not _check_cluster_token(self, mgr):
                return

            snapshot = mgr.state.get_state_snapshot()
            self._send_json(snapshot)
        except Exception:
            logger.exception("Failed to get cluster snapshot")
            self._send_error(500, "cluster snapshot unavailable")


__all__ = ["PicoDomeGetRoutesMixin"]
