from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from picosentry.sandbox import __version__
from picosentry.sandbox.l3.engine import get_backend

logger = logging.getLogger("picodome.health")

# Operational exceptions that a health probe is expected to hit when a
# component is unavailable or misconfigured.  Programmer errors (e.g.
# NameError, AttributeError) should propagate so they are noticed.
_HEALTH_PROBE_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
    ImportError,
)


@dataclass(frozen=True)
class HealthStatus:
    healthy: bool
    component: str
    detail: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "detail": self.detail,
            "healthy": self.healthy,
            "timestamp": self.timestamp,
        }


def check_health() -> list[HealthStatus]:
    checks: list[HealthStatus] = []
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    checks.append(
        HealthStatus(
            healthy=True,
            component="version",
            detail=__version__,
            timestamp=now,
        )
    )

    try:
        backend = get_backend()
        available = backend.is_available()
        checks.append(
            HealthStatus(
                healthy=available,
                component="sandbox_backend",
                detail=f"backend={backend.name} available={available}",
                timestamp=now,
            )
        )
    except _HEALTH_PROBE_ERRORS as exc:
        logger.warning("sandbox_backend health probe failed", exc_info=True)
        checks.append(
            HealthStatus(
                healthy=False,
                component="sandbox_backend",
                detail=f"error: {exc}",
                timestamp=now,
            )
        )

    try:
        from picosentry.sandbox.audit import get_audit_logger

        audit = get_audit_logger()
        stats = audit.get_stats()
        chain_ok = stats.get("chain_intact", True)
        checks.append(
            HealthStatus(
                healthy=chain_ok,
                component="audit_log",
                detail=f"events={stats.get('events', 0)} chain_intact={chain_ok}",
                timestamp=now,
            )
        )
    except _HEALTH_PROBE_ERRORS as exc:
        logger.warning("audit_log health probe failed", exc_info=True)
        checks.append(
            HealthStatus(
                healthy=False,
                component="audit_log",
                detail=f"error: {exc}",
                timestamp=now,
            )
        )

    try:
        from picosentry.sandbox.retention import get_retention_manager

        rm = get_retention_manager()
        storage = rm.get_storage_stats()
        checks.append(
            HealthStatus(
                healthy=True,
                component="storage",
                detail=f"scan_files={storage.get('scan_results', {}).get('file_count', 0)} "
                f"bytes={storage.get('total_bytes', 0)}",
                timestamp=now,
            )
        )
    except _HEALTH_PROBE_ERRORS as exc:
        logger.warning("storage health probe failed", exc_info=True)
        checks.append(
            HealthStatus(
                healthy=False,
                component="storage",
                detail=f"error: {exc}",
                timestamp=now,
            )
        )

    try:
        import os

        store_backend = os.environ.get("PICODOME_STORE_BACKEND", "jsonl")
        if store_backend.lower() == "sqlite":
            from picosentry.sandbox.daemon.sqlite_store import SQLiteScanJobStore

            store = SQLiteScanJobStore.from_env()
            count = store.count()
            checks.append(
                HealthStatus(
                    healthy=True,
                    component="store_backend",
                    detail=f"backend=sqlite jobs={count}",
                    timestamp=now,
                )
            )
        else:
            checks.append(
                HealthStatus(
                    healthy=True,
                    component="store_backend",
                    detail="backend=jsonl",
                    timestamp=now,
                )
            )
    except _HEALTH_PROBE_ERRORS as exc:
        logger.warning("store_backend health probe failed", exc_info=True)
        checks.append(
            HealthStatus(
                healthy=False,
                component="store_backend",
                detail=f"error: {exc}",
                timestamp=now,
            )
        )

    return checks


def check_readiness() -> HealthStatus:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    try:
        backend = get_backend()
        if not backend.is_available():
            return HealthStatus(
                healthy=False,
                component="readiness",
                detail=f"Backend {backend.name} not available",
                timestamp=now,
            )
        return HealthStatus(
            healthy=True,
            component="readiness",
            detail=f"Backend {backend.name} ready",
            timestamp=now,
        )
    except _HEALTH_PROBE_ERRORS as exc:
        logger.warning("readiness probe failed", exc_info=True)
        return HealthStatus(
            healthy=False,
            component="readiness",
            detail=f"Error: {exc}",
            timestamp=now,
        )
