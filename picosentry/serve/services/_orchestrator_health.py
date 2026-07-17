import logging
import os
import smtplib
import time
from datetime import datetime, timezone

from picosentry.serve.config.settings import settings
from picosentry.serve.database.manager import db
from picosentry.serve.services._orchestrator_data import BASE_DIR, _HEALTH_PROBE_ERRORS, ProjectMeta

logger = logging.getLogger("picoshogun.Orchestrator")


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
        checks.append(
            {
                "component": "database",
                "status": "critical",
                "message": str(e),
                "latency_ms": 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    try:
        stat = os.statvfs(str(BASE_DIR))
        free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
        total_gb = (stat.f_blocks * stat.f_frsize) / (1024**3)
        used_pct = (1 - stat.f_bavail / stat.f_blocks) * 100

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
        checks.append(
            {
                "component": "disk_space",
                "status": "unknown",
                "message": str(e),
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
        checks.append(
            {
                "component": "smtp",
                "status": "critical",
                "message": f"SMTP unreachable: {e}",
                "latency_ms": 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    return checks
