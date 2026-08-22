"""PicoShogun serve API.

Deployment support matrix (WO5.0.0-031):

| Mode            | Support                                                                  |
|-----------------|--------------------------------------------------------------------------|
| single worker   | fully supported (default; all state may be in-process)                   |
| multi worker    | supported with documented ceilings: event fanout latency = the outbox    |
| (API_WORKERS>1) | poll interval (default 1s); scheduler jobs may be skipped (never double- |
|                 | fired) across a leader takeover, and a job running longer than the lease |
|                 | TTL can overlap at takeover; rate limits sync every                       |
|                 | RATE_LIMIT_SYNC_SECONDS (default 5s) so bursts can overshoot by the      |
|                 | other workers' unsynced counts; /metrics is per-worker — aggregate via  |
|                 | labeled instances in the scraper, not in-process. A removed/disabled    |
|                 | job can fire once more if a standby takes over the leader lease before  |
|                 | the next reload_every (default 30s) — the leader's remove_job writes   |
|                 | to the DB, but a standby that wins the lease before its next reload    |
|                 | still holds the stale in-memory jobs list (WO6.0.0-020 documented      |
|                 | ceiling: a jobs-version column the standby polls would close this;     |
|                 | not implemented because the one-fire ceiling is the same order as the  |
|                 | lease-TTL overlap already documented above).                            |

The full matrix is also in deploy/helm/picosentry/README.md.
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from picosentry.serve.api.deps import auth_service
from picosentry.serve.api.routers import (
    admin,
    anomaly,
    auth,
    correlation,
    dashboard,
    health,
    metrics,
    orgs,
    plugins,
    projects,
    scans,
    webhooks,
    ws,
)
from picosentry.serve.api.routers import scheduler as scheduler_router
from picosentry.serve.config.logging_config import configure_logging
from picosentry.serve.config.settings import _env_bool, settings
from picosentry.serve.config.version import __version__
from picosentry.serve.database.manager import db
from picosentry.serve.errors import (
    AuthError,
    ConflictError,
    NotFoundError,
    PicoSentryError,
    QuotaExceededError,
    ServiceError,
    ValidationError,
)
from picosentry.serve.middleware.audit import AuditMiddleware
from picosentry.serve.middleware.cors_hardening import CORSHardeningMiddleware
from picosentry.serve.middleware.ddos_shield import DDoSShieldMiddleware
from picosentry.serve.middleware.docs_restriction import DocsRestrictionMiddleware
from picosentry.serve.middleware.https_enforcement import HTTPSEnforcementMiddleware
from picosentry.serve.middleware.rate_limit import RateLimitMiddleware
from picosentry.serve.middleware.request_id import RequestIDMiddleware
from picosentry.serve.middleware.request_size_limit import RequestSizeLimitMiddleware
from picosentry.serve.middleware.request_timeout import RequestTimeoutMiddleware
from picosentry.serve.middleware.security_headers import SecurityHeadersMiddleware
from picosentry.serve.services.anomaly_detector import AnomalyDetector
from picosentry.serve.services.event_bus import event_bus
from picosentry.serve.services.observability import init_telemetry, setup_fastapi_instrumentation
from picosentry.serve.services.plugin_manager import plugin_manager
from picosentry.serve.services.scheduler import scheduler


_correlation_imported = False
_alert_hub_imported = False
_webhook_manager_imported = False

# Cross-worker event fanout poller (started when multi-worker posture is
# on — API_WORKERS>1 or PICOSHOGUN_EVENT_OUTBOX=true). Module-level so
# repeated TestClient lifespans cannot stack pollers.
_outbox_poller = None


def _ensure_outbox_poller():
    global _outbox_poller

    from picosentry.serve.services.event_bus import OutboxPoller, event_bus

    if not settings.multiworker_enabled():
        return
    if _outbox_poller is not None and _outbox_poller.is_running():
        return
    event_bus.outbox_enabled = True
    _outbox_poller = OutboxPoller(
        event_bus,
        interval=settings.multiworker.event_outbox_poll_seconds,
        retention_seconds=settings.multiworker.event_outbox_retention_seconds,
    )
    _outbox_poller.start()
    logger.info("Event outbox fanout enabled (poll=%.2fs)", settings.multiworker.event_outbox_poll_seconds)


def _stop_outbox_poller():
    global _outbox_poller

    from picosentry.serve.services.event_bus import event_bus

    if _outbox_poller is not None:
        _outbox_poller.stop()
        _outbox_poller = None
    event_bus.outbox_enabled = False


def _stop_rate_limiter() -> None:
    """Stop the rate-limit background flush thread before db.close().

    Without this the flush thread keeps writing after the DB is closed,
    producing spurious persistence errors in the shutdown log (WO7.0.0-029).
    """
    node = getattr(app, "middleware_stack", None)
    while node is not None:
        if isinstance(node, RateLimitMiddleware):
            node.shutdown()
            return
        node = getattr(node, "app", None)


configure_logging(
    level=settings.logging.level,
    log_dir=settings.logging.log_dir if settings.logging.structured else None,
    structured=settings.logging.structured,
    max_bytes=settings.logging.max_bytes,
    backup_count=settings.logging.backup_count,
)

logger = logging.getLogger("picoshogun.api")


anomaly_detector = AnomalyDetector(db, alert_hub=None)  # alert_hub wired at startup


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("PicoShogun starting up — version %s", __version__)

    from picosentry.serve.services.websocket_manager import ws_manager

    ws_manager.main_loop = asyncio.get_running_loop()

    settings.assert_secure()

    config_issues = settings.validate()
    for issue in config_issues:
        if issue.startswith("CONFIG:"):
            logger.warning("CONFIG: %s", issue)

    init_telemetry(service_name="picoshogun")
    setup_fastapi_instrumentation(app)
    logger.info("OpenTelemetry initialized (if endpoint configured)")

    from picosentry.serve.services.alert_hub import AlertHub

    alert_hub = AlertHub()
    anomaly_detector.alert_hub = alert_hub
    logger.info("Alert hub wired to anomaly detector")

    from picosentry.serve.services.correlation import (
        correlation_engine,
    )
    from picosentry.serve.services.correlation.engine import CorrelationEngine
    from picosentry.serve.services.webhooks import webhook_manager

    from picosentry.serve.database.manager import db

    if CorrelationEngine.enable_persistence_if_supported():
        loaded = correlation_engine.load_events()
        logger.info("Correlation persistence ready — loaded %d event(s)", loaded)
    else:
        logger.info("Correlation persistence not available (run migrations first)")

    _alert_hub_global = alert_hub
    _webhook_manager_global = webhook_manager

    def _chain_escalated_alert(chain):
        try:
            chain_org = int(chain.org_id) if chain.org_id is not None else None
            _alert_hub_global.send(
                project_id=chain.artifact_id,
                alert_type="chain_escalated",
                severity="critical" if chain.chain_score >= 0.8 else "high",
                message=(
                    f"Kill chain for '{chain.artifact_id}' crossed critical threshold "
                    f"(score={chain.chain_score:.2f}). "
                    f"{chain.narrative[:200]}"
                ),
                metadata={
                    "chain_score": chain.chain_score,
                    "phases": list(chain.phases.keys()),
                    "severity": chain.severity.value,
                    "phase_count": len(chain.phases),
                    "event_count": sum(len(e) for e in chain.phases),
                },
                org_id=chain_org,
            )
        except (OSError, ValueError):
            logger.exception("Chain escalation alert failed")

    def _chain_escalated_webhook(chain):
        try:
            chain_org = next(
                (e.org_id for events in chain.phases.values() for e in events if e.org_id is not None),
                None,
            )
            _webhook_manager_global.dispatch(
                "chain.escalated",
                {
                    "artifact_id": chain.artifact_id,
                    "chain_score": chain.chain_score,
                    "severity": chain.severity.value,
                    "chain": chain.to_dict(),
                },
                org_id=chain_org,
            )
        except (OSError, ValueError):
            logger.exception("Chain escalation webhook failed")

    correlation_engine.on_chain_escalated(_chain_escalated_alert)
    correlation_engine.on_chain_escalated(_chain_escalated_webhook)
    logger.info("Correlation escalation callbacks wired")

    anomaly_detector.start()
    if settings.orchestrator.schedule_enabled:
        scheduler.start()
        logger.info("Anomaly detector and scheduler started")
    else:
        logger.info("Anomaly detector started (scheduler disabled by schedule_enabled=False)")

    _ensure_outbox_poller()

    expired_count = auth_service.cleanup_expired_keys()
    if expired_count:
        logger.info("Startup: deactivated %d expired API key(s)", expired_count)

    scheduler.add_job(
        name="periodic_cleanup",
        cron="0 */6 * * *",
        command="cleanup",
        params={},
        enabled=True,
        org_id=None,
    )

    if settings.database.backup_dir:
        scheduler.add_job(
            name="auto_backup",
            cron="0 2 * * *",
            command="backup",
            params={},
            enabled=True,
            org_id=None,
        )
        logger.info("Automatic daily backup scheduled at 02:00 UTC")

    health_interval = settings.orchestrator.health_check_interval
    if health_interval > 0:
        scheduler.add_job(
            name="health_check",
            cron=f"*/{health_interval // 60} * * * *" if health_interval >= 60 else "* * * * *",
            command="health_check",
            params={},
            enabled=True,
            org_id=None,
        )
        logger.info("Periodic health checks scheduled every %d seconds", health_interval)

    yield  # Application is running

    logger.info("PicoShogun shutting down — stopping background services")
    ws_manager.main_loop = None
    _stop_outbox_poller()
    _stop_rate_limiter()
    anomaly_detector.stop()
    scheduler.stop()
    event_bus.shutdown()
    plugin_manager.unload_all()
    db.close()

    try:
        from picosentry.serve.services.observability import shutdown_telemetry

        shutdown_telemetry()
    except (OSError, RuntimeError) as exc:
        logger.warning("Telemetry shutdown failed: %s", exc)

    logger.info("All background services stopped")


# In production, API docs are disabled unless the operator explicitly sets
# PICOSHOGUN_DOCS_URL or PICOSHOGUN_REDOC_URL.  FastAPI's docs_url=None
# prevents OpenAPI schema generation, which is the safest default for an
# untrusted-network deployment.
_docs_url = settings.api.docs_url if not settings.is_production() or _env_bool("DOCS_ENABLED") else None
_redoc_url = settings.api.redoc_url if not settings.is_production() or _env_bool("DOCS_ENABLED") else None

app = FastAPI(
    title="PicoShogun Command Centre API",
    description="Command centre for the Pico Security Series",
    version=__version__,
    docs_url=_docs_url,
    redoc_url=_redoc_url,
    lifespan=lifespan,
)


@app.exception_handler(PicoSentryError)
async def serve_error_handler(request: Request, exc: PicoSentryError):
    request_id = getattr(request.state, "request_id", "unknown")
    logger.warning("Serve error (%s) on %s %s", type(exc).__name__, request.method, request.url.path)
    mapping: dict[type[PicoSentryError], int] = {
        AuthError: 401,
        NotFoundError: 404,
        ValidationError: 422,
        ConflictError: 409,
        QuotaExceededError: 402,
        ServiceError: 500,
    }
    status = mapping.get(type(exc), 500)
    return JSONResponse(
        status_code=status,
        content={"error": type(exc).__name__, "detail": str(exc), "request_id": request_id},
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    import os

    request_id = getattr(request.state, "request_id", "unknown")
    logger.exception("Unhandled error in API request")
    if os.environ.get("PICOSHOGUN_ENV", "production") == "development":
        return JSONResponse(
            status_code=500,
            content={"error": "internal_server_error", "detail": str(exc), "request_id": request_id},
        )
    return JSONResponse(
        status_code=500,
        content={"error": "internal_server_error", "detail": "An unexpected error occurred", "request_id": request_id},
    )


api_v1 = APIRouter(prefix=settings.api.api_prefix)


app.add_middleware(
    RateLimitMiddleware,
    max_requests_per_ip=100,
    max_requests_per_org=1000,
    window=60,
    # Multi-worker: the memory backend alone enforces limits x workers, so
    # persistence goes on and counters re-sync on a short window. Residual
    # ceiling: within the sync window each worker undercounts the others
    # (see middleware/rate_limit.py). Redis, when configured, stays the
    # globally-atomic backend and needs none of this.
    persist=(settings.is_production() or settings.multiworker_enabled())
    and settings.security.rate_limit_backend != "redis",
    backend=settings.security.rate_limit_backend,
    backend_url=settings.security.redis_url,
    redis_fail_closed=settings.security.ratelimit_redis_fail_closed,
    exempt_paths={"/health", "/health/live", "/health/ready"},
    trusted_proxies=settings.security.trusted_proxies,
    sync_interval=(settings.multiworker.rate_limit_sync_seconds if settings.multiworker_enabled() else 60.0),
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "X-API-Key", "X-Org-API-Key", "X-Org-Id", "Content-Type", "X-Request-ID"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(DDoSShieldMiddleware, enabled=settings.security.ddos_shield_enabled)
app.add_middleware(RequestSizeLimitMiddleware, max_body_bytes=10 * 1024 * 1024)  # 10 MB
app.add_middleware(RequestIDMiddleware)
app.add_middleware(SecurityHeadersMiddleware)


app.add_middleware(
    RequestTimeoutMiddleware,
    timeout_seconds=30,
    long_running_paths=("/run", "/api/v1/sandboxes", "/api/v1/scans"),
)
app.add_middleware(HTTPSEnforcementMiddleware, enabled=settings.is_production())
app.add_middleware(DocsRestrictionMiddleware, enabled=settings.is_production())
app.add_middleware(CORSHardeningMiddleware, block_wildcard_in_production=settings.is_production())
# WO4.0.0-004: Audit added LAST = OUTERMOST, so rate-limited (429),
# oversized (413) and DDoS-blocked requests — which short-circuit in the
# middlewares below — still reach the tamper-evident audit log. RequestID
# sits inside audit, so blocked rows still carry the correlation id.
app.add_middleware(AuditMiddleware)


app.include_router(health.router)
app.include_router(projects.router)
app.include_router(auth.router)
app.include_router(orgs.router)
app.include_router(plugins.router)
app.include_router(webhooks.router)
app.include_router(scheduler_router.router)
app.include_router(admin.router)
app.include_router(anomaly.router)
app.include_router(correlation.router)
app.include_router(metrics.router)
app.include_router(ws.router)


api_v1.include_router(dashboard.router)
api_v1.include_router(scans.router)

app.include_router(api_v1)


try:
    from pathlib import Path as _Path

    _base = _Path(__file__).resolve().parent.parent / "front"
    _front = _base / "build"

    if not _front.is_dir() and (_base / "index.html").exists():
        _front = _base
    if _front.is_dir():
        app.mount("/static", StaticFiles(directory=str(_front)), name="static")
except (OSError, ImportError):
    logger.warning("Static files directory could not be mounted", exc_info=True)


def main() -> None:
    import signal

    import uvicorn

    def _graceful_shutdown(signum, _frame):
        sig_name = signal.strsignal(signum) or str(signum)
        logger.info("Received %s — initiating graceful shutdown", sig_name)
        # WO6.0.0-020: SIGTERM must stop the outbox poller too — post-`db.close()`
        # the poller re-opens connections and keeps polling during the shutdown
        # window. Matches the lifespan teardown order (line 268-275).
        # WO7.0.0-029: rate-limit flush thread must also stop before db.close().
        _stop_outbox_poller()
        _stop_rate_limiter()
        anomaly_detector.stop()
        scheduler.stop()
        event_bus.shutdown()
        plugin_manager.unload_all()
        db.close()
        logger.info("Graceful shutdown complete — exiting")
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _graceful_shutdown)
    signal.signal(signal.SIGINT, _graceful_shutdown)

    ssl_kwargs: dict[str, Any] = {}
    if settings.security.ssl_cert_path and settings.security.ssl_key_path:
        ssl_kwargs["ssl_certfile"] = str(settings.security.ssl_cert_path)
        ssl_kwargs["ssl_keyfile"] = str(settings.security.ssl_key_path)
        logger.info("TLS enabled: cert=%s", settings.security.ssl_cert_path)

    # Slowloris mitigation. ASGI middleware cannot bound header-read time — headers
    # are consumed by the server (uvicorn/h11/httptools) before any middleware runs,
    # and uvicorn exposes no header-read deadline. The two uvicorn levers that do cap
    # the classic slowloris resource-exhaustion vector are limit_concurrency (bounds
    # concurrent half-open connections) and limit_max_requests (bounds long-lived
    # connections). A true per-connection time-to-first-header deadline belongs at the
    # reverse-proxy layer (nginx/ingress `client_header_timeout`).
    limit_concurrency = int(os.environ.get("PICOSHOGUN_LIMIT_CONCURRENCY", "512"))
    limit_max_requests = int(os.environ.get("PICOSHOGUN_LIMIT_MAX_REQUESTS", "1000"))

    run_kwargs: dict[str, Any] = {
        "timeout_keep_alive": int(os.environ.get("PICOSHOGUN_KEEP_ALIVE", "30")),
        "timeout_graceful_shutdown": int(os.environ.get("PICOSHOGUN_GRACEFUL_SHUTDOWN", "15")),
        "limit_concurrency": limit_concurrency,
        "limit_max_requests": limit_max_requests,
        **ssl_kwargs,
    }
    if settings.api.workers > 1 or settings.api.reload:
        uvicorn.run(
            "picosentry.serve.api.server:app",
            host=settings.api.host,
            port=settings.api.port,
            workers=settings.api.workers,
            reload=settings.api.reload,
            **run_kwargs,
        )
    else:
        uvicorn.run(
            app,
            host=settings.api.host,
            port=settings.api.port,
            **run_kwargs,
        )


if __name__ == "__main__":
    main()
