import logging
import os
import smtplib
import threading
import time
from datetime import datetime, timezone

from picosentry.serve.config.settings import settings
from picosentry.serve.database.manager import db
from picosentry.serve.services._orchestrator_data import BASE_DIR, _HEALTH_PROBE_ERRORS, ProjectMeta

logger = logging.getLogger("picoshogun.Orchestrator")

# /health is unauthenticated, rate-limit-exempt and probed by load
# balancers; without a cache every hit re-probed DB/disk/SMTP and wrote
# 3-4 rows. The TTL bounds probe frequency (and therefore insert
# frequency) regardless of request rate.
HEALTH_CACHE_TTL_SECONDS = 15.0
# Hard cap on persisted history; /health/history never serves more than
# 1000 rows, so older rows are dead weight.
_HEALTH_RETENTION_ROWS = 1000

_cache_lock = threading.Lock()
_cached_checks: list[dict] | None = None
_cached_at: float = 0.0


def get_health_checks_cached(registry: dict[str, ProjectMeta]) -> list[dict]:
    """TTL-cached perform_health_checks, single-flight.

    The lock is held across the probe so concurrent callers share one
    result instead of stampeding the probes. Callers on the event loop
    must invoke this via asyncio.to_thread — the probes block.
    """
    global _cached_checks, _cached_at
    with _cache_lock:
        if _cached_checks is not None and time.monotonic() - _cached_at < HEALTH_CACHE_TTL_SECONDS:
            return _cached_checks
        checks = perform_health_checks(registry)
        _cached_at = time.monotonic()
        _cached_checks = checks
        return checks


def reset_health_cache() -> None:
    """Drop the cached probe result (tests, and after a DB restore)."""
    global _cached_checks, _cached_at
    with _cache_lock:
        _cached_checks = None
        _cached_at = 0.0


def perform_health_checks(registry: dict[str, ProjectMeta]) -> list[dict]:
    checks: list[dict] = []

    start = time.time()
    try:
        db.execute("SELECT 1")
        latency = (time.time() - start) * 1000
        checks.append(
            {
                "component": "database",
                "status": "healthy",
                "message": "Connected",
                "latency_ms": round(latency, 2),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    except _HEALTH_PROBE_ERRORS as e:
        logger.warning("Database health probe failed: %s", e)
        checks.append(
            {
                "component": "database",
                "status": "critical",
                "message": "Database unreachable",
                "latency_ms": 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    try:
        stat = os.statvfs(str(BASE_DIR))
        free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
        total_gb = (stat.f_blocks * stat.f_frsize) / (1024**3)
        used_pct = (1 - stat.f_bavail / stat.f_blocks) * 100

        # The disk_space_low anomaly rule reads this gauge; the health probe
        # is its only producer.
        from picosentry.serve.services.metrics import metrics

        metrics.gauge("disk_used_pct", round(used_pct, 2))

        status = "healthy" if used_pct < 80 else "warning" if used_pct < 90 else "critical"
        checks.append(
            {
                "component": "disk_space",
                "status": status,
                "message": f"{free_gb:.1f}GB free of {total_gb:.1f}GB ({used_pct:.1f}% used)",
                "latency_ms": 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    except OSError as e:
        logger.warning("Disk space probe failed: %s", e)
        checks.append(
            {
                "component": "disk_space",
                "status": "unknown",
                "message": "Disk space unavailable",
                "latency_ms": 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    project_count = len(registry)
    checks.append(
        {
            "component": "projects",
            "status": "healthy" if project_count > 0 else "warning",
            "message": f"{project_count} projects in registry",
            "latency_ms": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )

    for check in checks:
        db.execute_insert(
            """
            INSERT INTO health_checks (component, status, message, latency_ms)
            VALUES (?, ?, ?, ?)
        """,
            (check["component"], check["status"], check["message"], check["latency_ms"]),
        )

    try:
        db.execute(
            f"""
            DELETE FROM health_checks WHERE id NOT IN (
                SELECT id FROM health_checks ORDER BY created_at DESC, id DESC LIMIT {_HEALTH_RETENTION_ROWS}
            )
        """
        )
    except _HEALTH_PROBE_ERRORS:
        # Retention trim must never fail the probe itself.
        logger.debug("health_checks retention trim skipped", exc_info=True)

    start = time.time()
    try:
        if settings.alerts.email_smtp_host:
            with smtplib.SMTP(settings.alerts.email_smtp_host, settings.alerts.email_smtp_port, timeout=5) as server:
                if settings.alerts.email_smtp_starttls:
                    server.starttls()
                latency = (time.time() - start) * 1000
                checks.append(
                    {
                        "component": "smtp",
                        "status": "healthy",
                        "message": "SMTP reachable",
                        "latency_ms": round(latency, 2),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
        else:
            checks.append(
                {
                    "component": "smtp",
                    "status": "disabled",
                    "message": "SMTP not configured",
                    "latency_ms": 0,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
    except (OSError, smtplib.SMTPException) as e:
        logger.warning("SMTP health probe failed: %s", e)
        checks.append(
            {
                "component": "smtp",
                "status": "critical",
                "message": "SMTP unreachable",
                "latency_ms": 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    return checks
