from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

from picosentry.scan.auth import AuthConfig, AuthResult, RateLimiter, check_auth, check_authorization


_request_counter = 0
_request_counter_lock = threading.Lock()


def _logger():
    from picosentry.scan.daemon import logger

    return logger


class HealthHandler(BaseHTTPRequestHandler):
    auth_config: AuthConfig = AuthConfig()
    rate_limiter: RateLimiter = RateLimiter()
    _engine_cache: Any = None

    def log_message(self, _format: str, *args) -> None:
        _logger().debug("daemon: %s", _format % args)

    def _get_headers_dict(self) -> dict[str, str]:
        headers = {}
        for key, value in self.headers.items():
            headers[key.lower()] = value
        return headers

    def _request_id(self) -> str:
        global _request_counter
        rid = self.headers.get("X-Request-Id")
        if rid:
            return rid
        with _request_counter_lock:
            _request_counter += 1
            return f"req-{_request_counter:08x}"

    def _client_ip(self) -> str:
        direct_ip = self.client_address[0] if self.client_address else "unknown"
        if self.auth_config.trusted_proxies and direct_ip in self.auth_config.trusted_proxies:
            forwarded = self.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",")[0].strip()
        return direct_ip

    def _send_json(self, code: int, data: dict, request_id: str = "", start_time: float | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if request_id:
            self.send_header("X-Request-Id", request_id)
        if start_time is not None:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            self.send_header("X-Response-Time-Ms", f"{elapsed_ms:.1f}")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _check_auth(self, request_id: str) -> AuthResult:
        headers = self._get_headers_dict()

        path = self.path.split("?")[0].split("#")[0]
        if path in self.auth_config.public_endpoints and self.auth_config.mode != "off":
            _logger().info("request: public endpoint=%s request_id=%s", path, request_id)
            return AuthResult.success(identity="anonymous", token_type="none")

        result = check_auth(headers, self.auth_config)

        if not result.ok:
            self._send_json(
                401 if "Missing" in result.error else 403, {"error": result.error, "request_id": request_id}, request_id
            )
            _logger().warning("auth_failed: path=%s request_id=%s error=%s", path, request_id, result.error)
            from picosentry.scan.metrics import increment

            increment("auth.failures")
            return result

        _logger().info("auth_ok: identity=%s request_id=%s path=%s", result.identity, request_id, path)
        from picosentry.scan.metrics import increment

        increment("auth.requests")
        return result

    def _check_rate_limit(self, client_ip: str, request_id: str) -> bool:
        if not self.rate_limiter.check(client_ip):
            retry_after = self.rate_limiter.retry_after(client_ip)
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", str(retry_after))
            if request_id:
                self.send_header("X-Request-Id", request_id)
            self.end_headers()
            self.wfile.write(
                json.dumps({"error": "rate limited", "retry_after": retry_after, "request_id": request_id}).encode()
            )
            from picosentry.scan.metrics import increment

            increment("daemon.rate_limited")
            return False
        return True

    def do_GET(self) -> None:
        start_time = time.monotonic()
        client_ip = self._client_ip()
        request_id = self._request_id()

        try:
            if not self._check_rate_limit(client_ip, request_id):
                return

            path = self.path.split("?")[0].split("#")[0]

            if path in ("/health", "/healthz"):
                self._handle_health(request_id, start_time)
            elif path in ("/ready", "/readyz"):
                self._handle_readiness(request_id, start_time)
            elif path == "/metrics":
                auth_result = self._check_auth(request_id)
                if not auth_result.ok:
                    return
                authz = check_authorization(auth_result, "/metrics", "GET")
                if not authz.ok:
                    self._send_json(403, {"error": authz.error, "request_id": request_id}, request_id, start_time)
                    return
                self._handle_metrics(request_id, start_time)
            elif path == "/metrics/json":
                auth_result = self._check_auth(request_id)
                if not auth_result.ok:
                    return
                authz = check_authorization(auth_result, "/metrics/json", "GET")
                if not authz.ok:
                    self._send_json(403, {"error": authz.error, "request_id": request_id}, request_id, start_time)
                    return
                self._handle_metrics_json(request_id, start_time)
            elif path == "/dashboard":
                auth_result = self._check_auth(request_id)
                if not auth_result.ok:
                    return
                authz = check_authorization(auth_result, "/dashboard", "GET")
                if not authz.ok:
                    self._send_json(403, {"error": authz.error, "request_id": request_id}, request_id, start_time)
                    return
                tenant_id = self.headers.get("X-Tenant-Id")
                self._handle_dashboard(request_id, start_time, tenant_id=tenant_id)
            elif path == "/dashboard/tenants":
                auth_result = self._check_auth(request_id)
                if not auth_result.ok:
                    return

                authz = check_authorization(auth_result, "/dashboard/tenants", "GET")
                if not authz.ok:
                    self._send_json(403, {"error": authz.error, "request_id": request_id}, request_id, start_time)
                    return
                self._handle_dashboard_tenants(request_id, start_time)
            elif path == "/dashboard/fleet":
                auth_result = self._check_auth(request_id)
                if not auth_result.ok:
                    return

                authz = check_authorization(auth_result, "/dashboard/fleet", "GET")
                if not authz.ok:
                    self._send_json(403, {"error": authz.error, "request_id": request_id}, request_id, start_time)
                    return
                self._handle_dashboard_fleet(request_id, start_time)
            elif path == "/dashboard/compliance":
                auth_result = self._check_auth(request_id)
                if not auth_result.ok:
                    return

                authz = check_authorization(auth_result, "/dashboard/compliance", "GET")
                if not authz.ok:
                    self._send_json(403, {"error": authz.error, "request_id": request_id}, request_id, start_time)
                    return
                self._handle_dashboard_compliance(request_id, start_time)
            elif path == "/":
                auth_result = self._check_auth(request_id)
                if not auth_result.ok:
                    return
                self._handle_root(request_id, start_time)
            else:
                self.send_error(404, "Not Found")
        finally:
            from picosentry.scan.logging import clear_request_context

            clear_request_context()

    def do_POST(self) -> None:
        start_time = time.monotonic()
        client_ip = self._client_ip()
        request_id = self._request_id()

        try:
            if not self._check_rate_limit(client_ip, request_id):
                return

            path = self.path.split("?")[0].split("#")[0]

            if path == "/scan":
                auth_result = self._check_auth(request_id)
                if not auth_result.ok:
                    return

                from picosentry.scan.auth import check_authorization

                authz = check_authorization(auth_result, "/scan", "POST")
                if not authz.ok:
                    self._send_json(403, {"error": authz.error, "request_id": request_id}, request_id, start_time)
                    return

                self._handle_scan(request_id, start_time)
            else:
                self.send_error(404, "Not Found")
        finally:
            from picosentry.scan.logging import clear_request_context

            clear_request_context()

    def _handle_scan(self, request_id: str = "", start_time: float | None = None) -> None:
        import json as _json

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            data = _json.loads(body) if body else {}
        except (ValueError, UnicodeDecodeError):
            self._send_json(400, {"error": "Invalid JSON body", "request_id": request_id}, request_id, start_time)
            return

        target = data.get("target", "")
        rules = data.get("rules")
        _fmt = data.get("format", "json")

        if not target:
            self._send_json(400, {"error": "Missing 'target' field", "request_id": request_id}, request_id, start_time)
            return

        if Path(target).is_absolute() or ".." in target:
            self._send_json(
                400,
                {"error": "Scan target must be a relative path under the workspace root", "request_id": request_id},
                request_id,
                start_time,
            )
            return
        scan_root = Path(os.environ.get("PICOSENTRY_SCAN_ROOT") or Path.cwd())
        scan_root_real = scan_root.resolve()
        resolved = (scan_root_real / target).resolve()
        if not resolved.is_relative_to(scan_root_real):
            self._send_json(
                400, {"error": "Scan target escapes workspace root", "request_id": request_id}, request_id, start_time
            )
            return
        target = str(resolved)

        try:
            from picosentry.scan.engine import create_default_engine

            engine = create_default_engine()
            result = engine.scan(target, rules=rules)

            from picosentry.scan.formatters.json_fmt import format_json

            output = format_json(result)
            self._send_json(200, _json.loads(output) if isinstance(output, str) else output, request_id, start_time)
        except (OSError, RuntimeError, ValueError, TypeError):
            _logger().exception("Scan failed")
            self._send_json(500, {"error": "scan execution failed", "request_id": request_id}, request_id, start_time)

    def _handle_health(self, request_id: str = "", start_time: float | None = None) -> None:
        self._send_json(200, {"status": "healthy", "request_id": request_id}, request_id, start_time)

    def _handle_readiness(self, request_id: str = "", start_time: float | None = None) -> None:
        try:
            engine = HealthHandler._engine_cache
            if engine is None:
                from picosentry.scan.engine import create_default_engine

                engine = create_default_engine()
                HealthHandler._engine_cache = engine
            status = {
                "status": "ready",
                "version": engine._corpus_version,
                "rules": len(engine.list_rules()),
                "request_id": request_id,
            }
            self._send_json(200, status, request_id, start_time)
        except (OSError, RuntimeError, ValueError, TypeError, ImportError) as e:
            _logger().warning("Readiness check: engine init failed: %s", e)
            status = {"status": "not_ready", "reason": "engine_init_failed", "request_id": request_id}
            self._send_json(503, status, request_id, start_time)

    def _handle_metrics(self, request_id: str = "", start_time: float | None = None) -> None:
        from picosentry.scan.metrics import get_metrics

        metrics = get_metrics().snapshot()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        if request_id:
            self.send_header("X-Request-Id", request_id)
        if start_time is not None:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            self.send_header("X-Response-Time-Ms", f"{elapsed_ms:.1f}")
        self.end_headers()
        self.wfile.write(metrics.to_prometheus().encode())

    def _handle_metrics_json(self, request_id: str = "", start_time: float | None = None) -> None:
        from picosentry.scan.metrics import get_metrics

        metrics = get_metrics().snapshot()
        self._send_json(200, metrics.to_dict(), request_id, start_time)

    def _handle_root(self, request_id: str = "", start_time: float | None = None) -> None:
        from picosentry import __version__

        info = {
            "service": "picosentry",
            "version": __version__,
            "auth_mode": self.auth_config.mode,
            "request_id": request_id,
            "endpoints": {
                "/health": "Liveness probe",
                "/ready": "Readiness probe",
                "/metrics": "Prometheus metrics (auth required)",
                "/metrics/json": "JSON metrics (auth required)",
                "/dashboard": "Enterprise dashboard (auth required)",
                "/dashboard/tenants": "Tenant list and health (auth required)",
                "/dashboard/fleet": "Fleet rollout status (auth required)",
                "/dashboard/compliance": "Compliance report (auth required)",
                "/scan": "Trigger supply chain scan (POST, auth required)",
            },
        }
        self._send_json(200, info, request_id, start_time)

    def _handle_dashboard(
        self, request_id: str = "", start_time: float | None = None, tenant_id: str | None = None
    ) -> None:
        from picosentry import __version__
        from picosentry.scan.metrics import get_metrics

        metrics = get_metrics().snapshot()

        advisory_status = "not_loaded"
        advisory_count = 0
        has_errors = False
        try:
            from picosentry.scan.advisory import load_bundled_advisories

            db = load_bundled_advisories()
            if db.is_loaded:
                advisory_status = "loaded"
                advisory_count = db.advisory_count
        except (OSError, RuntimeError, ImportError, ValueError, TypeError):
            advisory_status = "error"
            has_errors = True

        tenant_summary = {"enabled": 0, "disabled": 0, "total": 0}
        try:
            from picosentry.scan.tenant import TenantManager

            tm = TenantManager()
            if tenant_id:
                health = tm.tenant_health(tenant_id)
                if health.get("status") == "not_found":
                    self._send_json(
                        404,
                        {"error": f"Tenant {tenant_id} not found", "request_id": request_id},
                        request_id,
                        start_time,
                    )
                    return
                tenant_summary = {
                    "total": 1,
                    "enabled": 1 if health.get("enabled") else 0,
                    "disabled": 0 if health.get("enabled") else 1,
                }
            else:
                overview = tm.fleet_overview()
                tenant_summary = {
                    "total": overview["total_tenants"],
                    "enabled": overview["enabled_tenants"],
                    "disabled": overview["disabled_tenants"],
                }
        except (OSError, RuntimeError, ImportError, ValueError, TypeError):
            _logger().warning("Dashboard tenant summary failed", exc_info=True)

        fleet_summary = {"active_rollouts": 0, "failed_rollouts": 0, "total_targets": 0}
        try:
            from picosentry.scan.fleet import FleetManager

            fm = FleetManager()
            health = fm.fleet_health()
            fleet_summary = {
                "total_targets": health["total_targets"],
                "compliant_targets": health["compliant_targets"],
                "active_rollouts": health["active_rollouts"],
                "failed_rollouts": health["failed_rollouts"],
            }
        except (OSError, RuntimeError, ImportError, ValueError, TypeError):
            _logger().warning("Dashboard fleet summary failed", exc_info=True)

        dashboard = {
            "service": "picosentry",
            "version": __version__,
            "status": "healthy" if not has_errors else "degraded",
            "uptime_seconds": round(metrics.uptime_seconds, 1),
            "request_id": request_id,
            "advisory_db": {
                "status": advisory_status,
                "advisory_count": advisory_count,
            },
            "tenants": tenant_summary,
            "fleet": fleet_summary,
            "metrics": {
                "scans_total": metrics.counters.get("scans.total", 0),
                "findings_total": metrics.counters.get("findings.total", 0),
                "auth_failures": metrics.counters.get("auth.failures", 0),
                "daemon_rate_limited": metrics.counters.get("daemon.rate_limited", 0),
            },
            "endpoints": {
                "/dashboard": "This overview",
                "/dashboard/tenants": "Tenant list and health",
                "/dashboard/fleet": "Fleet rollout status",
                "/dashboard/compliance": "Compliance report",
                "/health": "Liveness probe",
                "/metrics": "Prometheus metrics",
                "/scan": "Trigger scan (POST)",
            },
        }
        self._send_json(200 if not has_errors else 503, dashboard, request_id, start_time)

    def _handle_dashboard_tenants(self, request_id: str = "", start_time: float | None = None) -> None:
        try:
            from picosentry.scan.tenant import TenantManager

            tm = TenantManager()
            tenant_id = self.headers.get("X-Tenant-Id")
            if tenant_id:
                health = tm.tenant_health(tenant_id)
                if health.get("status") == "not_found":
                    self._send_json(
                        404,
                        {"error": f"Tenant {tenant_id} not found", "request_id": request_id},
                        request_id,
                        start_time,
                    )
                    return
                self._send_json(200, health, request_id, start_time)
            else:
                overview = tm.fleet_overview()
                self._send_json(200, overview, request_id, start_time)
        except (OSError, RuntimeError, ImportError, ValueError, TypeError):
            _logger().warning("Dashboard tenants failed", exc_info=True)
            self._send_json(
                503,
                {"tenants": {}, "total_tenants": 0, "error": "tenant subsystem unavailable"},
                request_id,
                start_time,
            )

    def _handle_dashboard_fleet(self, request_id: str = "", start_time: float | None = None) -> None:
        try:
            from picosentry.scan.fleet import FleetManager

            fm = FleetManager()
            health = fm.fleet_health()
            rollouts = []
            for r in fm.list_rollouts():
                s = fm.get_rollout_status(r.name)
                rollouts.append({"name": r.name, "current_stage": s.current_stage if s else ""})
            result = {"fleet_health": health, "rollouts": rollouts}
            tenant_id = self.headers.get("X-Tenant-Id")
            if tenant_id:
                result["tenant_id"] = tenant_id
            self._send_json(200, result, request_id, start_time)
        except (OSError, RuntimeError, ImportError, ValueError, TypeError):
            _logger().warning("Dashboard fleet failed", exc_info=True)
            self._send_json(
                503,
                {"fleet_health": {}, "rollouts": [], "error": "fleet subsystem unavailable"},
                request_id,
                start_time,
            )

    def _handle_dashboard_compliance(self, request_id: str = "", start_time: float | None = None) -> None:
        try:
            from picosentry.scan.fleet import FleetManager

            fm = FleetManager()
            report = fm.compliance_report()
            tenant_id = self.headers.get("X-Tenant-Id")
            if tenant_id:
                report["tenant_id"] = tenant_id
            self._send_json(200, report, request_id, start_time)
        except (OSError, RuntimeError, ImportError, ValueError, TypeError):
            _logger().warning("Dashboard compliance failed", exc_info=True)
            self._send_json(503, {"error": "compliance subsystem unavailable"}, request_id, start_time)
