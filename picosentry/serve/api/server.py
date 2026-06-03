"""REST API for PicoShogun — security orchestration & intelligence platform.

Route handlers live in api/routers/ — this module wires the FastAPI app,
lifecycle, middleware, and static files only.
"""
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from picosentry.serve.api.deps import auth_service
from picosentry.serve.api.routers import admin, anomaly, auth, correlation, dashboard, health, metrics, orgs, plugins, projects, scans, webhooks, ws
from picosentry.serve.api.routers import scheduler as scheduler_router
from picosentry.serve.config.logging_config import configure_logging
from picosentry.serve.config.settings import settings
from picosentry.serve.config.version import __version__
from picosentry.serve.database.manager import db
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

# Late imports to avoid circular dependencies
_correlation_imported = False
_alert_hub_imported = False
_webhook_manager_imported = False

# ─── Configure structured logging ──────────────────────────────────────
configure_logging(
    level=settings.logging.level,
    log_dir=settings.logging.log_dir if settings.logging.structured else None,
    structured=settings.logging.structured,
    max_bytes=settings.logging.max_bytes,
    backup_count=settings.logging.backup_count,
)

logger = logging.getLogger("picoshogun.api")

# ─── Service instances (created before app for lifespan access) ─────
anomaly_detector = AnomalyDetector(db, alert_hub=None)  # alert_hub wired at startup


# ─── Application lifecycle ──────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle.

    Starts: structured logging, OpenTelemetry, scheduler, anomaly detector.
    Stops: scheduler, anomaly detector, event bus, plugin manager, DB connections.
    """
    logger.info("PicoShogun starting up — version %s", __version__)

    # Enforce secure configuration — refuse to start with insecure defaults in production
    settings.assert_secure()

    # Log any non-critical config warnings
    config_issues = settings.validate()
    for issue in config_issues:
        if issue.startswith("CONFIG:"):
            logger.warning("CONFIG: %s", issue)

    # OpenTelemetry (graceful no-op if not configured)
    init_telemetry(service_name="picoshogun")
    setup_fastapi_instrumentation(app)
    logger.info("OpenTelemetry initialized (if endpoint configured)")

    # Wire alert_hub into anomaly detector now that all services are ready
    from picosentry.serve.services.alert_hub import AlertHub
    alert_hub = AlertHub()
    anomaly_detector.alert_hub = alert_hub
    logger.info("Alert hub wired to anomaly detector")

    # ── Correlation engine initialization (Phase 3+4) ───────────────
    from picosentry.serve.services.correlation import (
        correlation_engine,
    )
    from picosentry.serve.services.orchestrator import PICO_CLI
    from picosentry.serve.services.webhooks import webhook_manager

    # Try to enable persistence (DB table must exist from migration)
    try:
        from picosentry.serve.database.manager import db
        db.execute("SELECT 1 FROM correlation_events LIMIT 1")
        correlation_engine.PERSIST_ENABLED = True
        loaded = correlation_engine.load_events()
        logger.info("Correlation persistence ready — loaded %d event(s)", loaded)
    except Exception:
        correlation_engine.PERSIST_ENABLED = False
        logger.info("Correlation persistence not available (run migrations first)")

    # Wire escalation callbacks: AlertHub + WebhookManager → kill chains
    _alert_hub_global = alert_hub
    _webhook_manager_global = webhook_manager

    def _chain_escalated_alert(chain):
        """Send alert when a chain crosses critical threshold."""
        try:
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
                    "event_count": sum(len(e) for e in chain.phases.values()),
                },
            )
        except Exception as exc:
            logger.error("Chain escalation alert failed: %s", exc)

    def _chain_escalated_webhook(chain):
        """Fire webhook event when chain crosses critical threshold."""
        try:
            _webhook_manager_global.dispatch(
                "chain.escalated",
                {
                    "artifact_id": chain.artifact_id,
                    "chain_score": chain.chain_score,
                    "severity": chain.severity.value,
                    "chain": chain.to_dict(),
                },
            )
        except Exception as exc:
            logger.error("Chain escalation webhook failed: %s", exc)

    correlation_engine.on_chain_escalated(_chain_escalated_alert)
    correlation_engine.on_chain_escalated(_chain_escalated_webhook)
    logger.info("Correlation escalation callbacks wired")

    # Subscribe to auto_analyze events for cross-layer analysis
    def _on_auto_analyze(event):
        """Handle auto_analyze events by triggering downstream orchestration."""
        payload = event.payload
        downstream = payload.get("downstream_project", "")
        target = payload.get("target", "")
        if downstream and target and downstream in PICO_CLI:
            logger.info(
                "Auto-analyze queued: %s → %s (%s)",
                payload.get("source_project", "?"), downstream, target,
            )
            # Emit a project.run.requested event for the scheduler/orchestrator
            event_bus.publish(
                "project.run.requested",
                {
                    "project_id": downstream,
                    "target": target,
                    "trigger": "correlation_auto_analysis",
                    "source_artifact": payload.get("artifact_id"),
                    "source_run_id": payload.get("run_id"),
                },
                source="correlation_engine",
                priority="high",
            )

    event_bus.subscribe(
        "project.run.auto_analyze",
        _on_auto_analyze,
        persistent=True,
        subscriber_id="correlation-auto-analyze",
    )
    logger.info("Cross-layer auto-analysis subscriber registered")

    # Start background services
    anomaly_detector.start()
    if settings.orchestrator.schedule_enabled:
        scheduler.start()
        logger.info("Anomaly detector and scheduler started")
    else:
        logger.info("Anomaly detector started (scheduler disabled by schedule_enabled=False)")

    # Cleanup expired API keys on startup
    expired_count = auth_service.cleanup_expired_keys()
    if expired_count:
        logger.info("Startup: deactivated %d expired API key(s)", expired_count)

    # Schedule periodic cleanup: API keys, logs, audit entries every 6 hours
    scheduler.add_job(
        name="periodic_cleanup",
        cron="0 */6 * * *",
        command="cleanup",
        params={},
        enabled=True,
    )

    # Schedule periodic health checks at configured interval
    health_interval = settings.orchestrator.health_check_interval
    if health_interval > 0:
        scheduler.add_job(
            name="health_check",
            cron=f"*/{health_interval // 60} * * * *" if health_interval >= 60 else "* * * * *",
            command="health_check",
            params={},
            enabled=True,
        )
        logger.info("Periodic health checks scheduled every %d seconds", health_interval)

    yield  # Application is running

    # ── Graceful shutdown ──
    logger.info("PicoShogun shutting down — stopping background services")
    anomaly_detector.stop()
    scheduler.stop()
    event_bus.shutdown()
    plugin_manager.unload_all()
    db.close()
    logger.info("All background services stopped")


# ─── FastAPI app ──────────────────────────────────────────────────────────

app = FastAPI(
    title="PicoShogun Command Centre API",
    description="Command centre for the Pico Security Series",
    version=__version__,
    docs_url=settings.api.docs_url,
    redoc_url=settings.api.redoc_url,
    lifespan=lifespan,
)


# ─── Global exception handler ────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Return structured JSON for unhandled exceptions instead of HTML tracebacks."""
    request_id = getattr(request.state, "request_id", "unknown")
    logger.error(
        "Unhandled exception on %s %s [request_id=%s]: %s",
        request.method, request.url.path, request_id, exc,
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "detail": "An unexpected error occurred. Please try again later.",
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


# ─── API v1 router ──────────────────────────────────────────────────────

api_v1 = APIRouter(prefix=settings.api.api_prefix)


# ─── Middleware (order matters — last added = outermost) ─────────────────
# Execution order (outermost → innermost):
#   SecurityHeaders → RequestID → RequestSizeLimit → DDoSShield
#   → GZip → CORS → RateLimit → Audit
app.add_middleware(AuditMiddleware)
app.add_middleware(
    RateLimitMiddleware,
    max_requests_per_ip=100,
    max_requests_per_org=1000,
    window=60,
    persist=settings.is_production(),
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(DDoSShieldMiddleware, enabled=settings.security.ddos_shield_enabled)
app.add_middleware(RequestSizeLimitMiddleware, max_body_bytes=10 * 1024 * 1024)  # 10 MB
app.add_middleware(RequestIDMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# ── Security middleware ──────────────────────────────
app.add_middleware(RequestTimeoutMiddleware, timeout_seconds=30)
app.add_middleware(HTTPSEnforcementMiddleware, enabled=settings.is_production())
app.add_middleware(DocsRestrictionMiddleware, enabled=settings.is_production())
app.add_middleware(CORSHardeningMiddleware, block_wildcard_in_production=settings.is_production())


# ─── Unversioned routes (health, dashboard, projects, etc.) ─────────────

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


# ─── API v1 routes ───────────────────────────────────────────────────────

api_v1.include_router(dashboard.router)
api_v1.include_router(scans.router)

app.include_router(api_v1)


# ─── Static files (frontend dashboard) ───────────────────────────────────

try:
    from pathlib import Path as _Path
    _base = _Path(__file__).resolve().parent.parent / "front"
    _front = _base / "build"
    # Fall back to source front/ if no build/ directory exists
    if not _front.is_dir() and (_base / "index.html").exists():
        _front = _base
    if _front.is_dir():
        app.mount("/static", StaticFiles(directory=str(_front)), name="static")
except Exception:
    pass


# ─── Entry point ─────────────────────────────────────────────────────────

def main() -> None:
    """CLI entry point — starts the PicoShogun server with signal handling."""
    import signal

    import uvicorn

    def _graceful_shutdown(signum, frame):
        """Handle SIGTERM/SIGINT by stopping background services before exit."""
        sig_name = signal.strsignal(signum) or str(signum)
        logger.info("Received %s — initiating graceful shutdown", sig_name)
        anomaly_detector.stop()
        scheduler.stop()
        event_bus.shutdown()
        plugin_manager.unload_all()
        db.close()
        logger.info("Graceful shutdown complete — exiting")
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _graceful_shutdown)
    signal.signal(signal.SIGINT, _graceful_shutdown)

    # Uvicorn requires import string (not app object) when workers > 1 or reload is enabled
    # Build SSL kwargs if cert/key configured
    ssl_kwargs = {}
    if settings.security.ssl_cert_path and settings.security.ssl_key_path:
        ssl_kwargs["ssl_certfile"] = str(settings.security.ssl_cert_path)
        ssl_kwargs["ssl_keyfile"] = str(settings.security.ssl_key_path)
        logger.info("TLS enabled: cert=%s", settings.security.ssl_cert_path)

    if settings.api.workers > 1 or settings.api.reload:
        uvicorn.run(
            "picosentry.serve.api.server:app",
            host=settings.api.host,
            port=settings.api.port,
            workers=settings.api.workers,
            reload=settings.api.reload,
            **ssl_kwargs,
        )
    else:
        uvicorn.run(
            app,
            host=settings.api.host,
            port=settings.api.port,
            **ssl_kwargs,
        )


if __name__ == "__main__":
    main()
