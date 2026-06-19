import json
import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from picosentry.serve.config.settings import settings
from picosentry.serve.database.manager import db
from picosentry.serve.services.alert_hub import AlertHub
from picosentry.serve.services.correlation import (
    build_event_from_intel,
    correlation_engine,
)
from picosentry.serve.services.event_bus import event_bus
from picosentry.serve.services.intelligence import IntelligenceEngine
from picosentry.serve.services.metrics import metrics
from picosentry.serve.services.plugin_manager import plugin_manager

logger = logging.getLogger("picoshogun.Orchestrator")

BASE_DIR = Path(__file__).parent.parent
REGISTRY_PATH = BASE_DIR / "config" / "project_registry.json"


PICO_CLI = {
    "picosentry": ["picosentry", "scan"],
    "picodome": ["picosentry", "sandbox", "run"],
    "picowatch": ["picosentry", "watch", "scan-prompt"],
    "picoshogun": ["picosentry", "health"],
}


PROJECT_LAYER_MAP: dict[str, str] = {
    "picosentry": "scan",
    "picodome": "sandbox_l3",
    "picowatch": "watch",
}


@dataclass
class ProjectMeta:
    id: str
    name: str
    category: str
    priority: int
    dependencies: list[str]
    cron_schedule: str
    estimated_duration: int
    status: str = "pending"
    version: str = "1.0.1"
    intelligence_outputs: list[str] | None = None
    intelligence_inputs: list[str] | None = None
    description: str = ""
    package: str = ""


class EnhancedOrchestrator:  # rationale: async execution engine coordinating PicoSentry, PicoDome, PicoWatch
    def __init__(self):
        self.registry: dict[str, ProjectMeta] = {}
        self.intel = IntelligenceEngine()
        self.alerts = AlertHub()
        self._running = False
        self._start_time = time.time()
        self._concurrent_limit = settings.orchestrator.max_concurrent_projects
        self._semaphore = threading.Semaphore(self._concurrent_limit)
        self._load_registry()
        self._init_projects_db()

        event_bus.subscribe(
            "project.run.completed",
            lambda evt: correlation_engine.on_run_completed(
                project_id=evt.payload.get("project_id", ""),
                run_id=str(evt.payload.get("run_id", "")),
            ),
            persistent=True,
            subscriber_id="correlation-engine",
        )

    def _load_registry(self):
        if REGISTRY_PATH.exists():
            with open(REGISTRY_PATH) as f:
                data = json.load(f)
                for pid, pdict in data.items():
                    self.registry[pid] = ProjectMeta(**pdict)
            logger.info("Loaded %s projects from registry", len(self.registry))

    def _init_projects_db(self):
        for pid, meta in self.registry.items():
            existing = db.execute_one("SELECT id FROM projects WHERE id = ?", (pid,))
            if not existing:
                db.execute_insert(
                    """
                    INSERT INTO projects (id, name, category, priority, status, version)
                    VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (pid, meta.name, meta.category, meta.priority, meta.status, meta.version),
                )

    def get_status(self) -> dict[str, Any]:
        conn_stats = db.execute_one(f"""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
            FROM project_runs
            WHERE run_start > {db.dialect.date_add_hours("now", -24)}
        """)

        threats = db.execute_one(f"""
            SELECT COUNT(*) as count FROM intelligence
            WHERE severity IN ('critical', 'high')
            AND created_at > {db.dialect.date_add_hours("now", -24)}
        """)

        pending = db.execute_one("""
            SELECT COUNT(*) as count FROM alerts WHERE sent = 0
        """)

        health = "healthy"
        failed = (conn_stats["failed"] or 0) if conn_stats else 0
        completed = (conn_stats["completed"] or 0) if conn_stats else 0
        if failed > completed * 0.3 and completed > 0:
            health = "degraded"
        if threats and (threats["count"] or 0) > 10:
            health = "critical"

        running_row = db.execute_one("SELECT COUNT(*) as c FROM project_runs WHERE status = 'running'")
        return {
            "projects_total": len(self.registry),
            "projects_active": (running_row or {}).get("c") or 0,
            "projects_failed": failed,
            "active_threats": (threats["count"] or 0) if threats else 0,
            "pending_alerts": (pending["count"] or 0) if pending else 0,
            "threat_score": self.intel.get_aggregate_score(),
            "system_health": health,
            "uptime_seconds": time.time() - self._start_time,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def list_projects(
        self, category: str | None = None, status_filter: str | None = None, limit: int = 100, offset: int = 0
    ) -> list[dict]:
        query = "SELECT * FROM projects WHERE 1=1"
        params: list[str | int] = []

        if category:
            query += " AND category = ?"
            params.append(category)
        if status_filter:
            query += " AND status = ?"
            params.append(status_filter)

        query += " ORDER BY priority DESC, name LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = db.execute(query, tuple(params))
        return [dict(row) for row in rows]

    def get_project(self, project_id: str) -> dict | None:
        row = db.execute_one("SELECT * FROM projects WHERE id = ?", (project_id,))
        return dict(row) if row else None

    def run_project(self, project_id: str, timeout: int | None = None) -> dict[str, Any]:
        meta = self.registry.get(project_id)
        if not meta:
            return {"error": f"Unknown project: {project_id}"}

        cli_args = PICO_CLI.get(project_id, [meta.package or project_id])
        timeout = timeout or settings.orchestrator.default_timeout

        with self._semaphore:
            return self._execute_project(project_id, cli_args, timeout)

    def _execute_project(self, project_id: str, cli_args: list[str], timeout: int) -> dict[str, Any]:

        run_id = db.execute_insert(
            """
            INSERT INTO project_runs (project_id, run_start, status)
            VALUES (?, ?, ?)
        """,
            (project_id, datetime.now(timezone.utc), "running"),
        )

        event_bus.publish(
            "project.run.started",
            {"project_id": project_id, "run_id": run_id, "status": "running"},
            source="orchestrator",
            priority="normal",
        )

        start_time = time.time()

        try:
            cmd = cli_args

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )

            duration = time.time() - start_time

            intel_data = self.intel.extract_from_output(project_id, result.stdout + result.stderr)

            if result.returncode == 0:
                status = "completed"
            else:
                status = "failed"

                if settings.orchestrator.retry_failed:
                    retry_count = db.execute_one(
                        f"""
                        SELECT COUNT(*) as c FROM project_runs
                        WHERE project_id = ? AND status = 'failed'
                        AND run_start > {db.dialect.date_add_hours("now", -1)}
                    """,
                        (project_id,),
                    )
                    if retry_count and retry_count["c"] < settings.orchestrator.retry_max:
                        logger.info("Will retry %s after %ss", project_id, settings.orchestrator.retry_delay)

            db.execute_insert(
                """
                UPDATE project_runs
                SET run_end = ?, status = ?, exit_code = ?,
                    output = ?, stderr = ?, duration_seconds = ?,
                    intelligence_extracted = ?, alerts_generated = ?
                WHERE id = ?
            """,
                (
                    datetime.now(timezone.utc),
                    status,
                    result.returncode,
                    result.stdout,
                    result.stderr,
                    duration,
                    json.dumps(intel_data),
                    len(intel_data),
                    run_id,
                ),
            )

            self._update_project_stats(project_id)

            metrics.project_run(project_id, duration, status)

            event_bus.publish(
                "project.run.completed",
                {
                    "project_id": project_id,
                    "run_id": run_id,
                    "status": status,
                    "duration": round(duration, 2),
                    "exit_code": result.returncode,
                    "intelligence_count": len(intel_data),
                },
                source="orchestrator",
                priority="high" if status == "failed" else "normal",
            )

            for intel in intel_data:
                self.intel.ingest(project_id, intel)

            layer = PROJECT_LAYER_MAP.get(project_id, "scan")
            correlated_events = []
            for intel in intel_data:
                event = build_event_from_intel(
                    intel,
                    project_id,
                    run_id=str(run_id),
                    layer=layer,
                )
                if event is not None:
                    correlated_events.append(event)
            if correlated_events:
                correlation_engine.ingest_many(correlated_events)

            if status == "failed":
                self.alerts.send(
                    project_id,
                    "project_failed",
                    "high",
                    f"Project {project_id} failed with exit code {result.returncode}. "
                    f"Intel signals: {len(intel_data)}. "
                    f"Stderr: {result.stderr[:200]}",
                    metadata={"exit_code": result.returncode, "run_id": run_id, "intelligence_count": len(intel_data)},
                )

            plugin_manager.dispatch(
                "project_complete",
                project_id=project_id,
                result={
                    "status": status,
                    "duration": round(duration, 2),
                    "exit_code": result.returncode,
                    "intelligence_count": len(intel_data),
                    "success": result.returncode == 0,
                },
            )

            if status == "failed":
                plugin_manager.dispatch(
                    "alert",
                    alert={
                        "project_id": project_id,
                        "severity": "high",
                        "message": f"Project {project_id} failed",
                        "exit_code": result.returncode,
                    },
                )

            logger.info("%s: %s in %.1fs", project_id, status, duration)

            return {
                "success": result.returncode == 0,
                "duration": duration,
                "output": result.stdout[:5000],
                "stderr": result.stderr[:2000],
                "intelligence_count": len(intel_data),
            }

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            db.execute_insert(
                """
                UPDATE project_runs
                SET run_end = ?, status = ?, duration_seconds = ?
                WHERE id = ?
            """,
                (datetime.now(timezone.utc), "timeout", duration, run_id),
            )

            self.alerts.send(project_id, "timeout", "high", f"Project timed out after {timeout}s")

            plugin_manager.dispatch(
                "alert",
                alert={
                    "project_id": project_id,
                    "severity": "high",
                    "message": f"Project {project_id} timed out after {timeout}s",
                },
            )

            event_bus.publish(
                "project.run.failed",
                {"project_id": project_id, "run_id": run_id, "reason": "timeout", "duration": round(duration, 2)},
                source="orchestrator",
                priority="critical",
            )

            return {"error": "timeout", "duration": duration}

        except Exception as e:
            duration = time.time() - start_time
            db.execute_insert(
                """
                UPDATE project_runs
                SET run_end = ?, status = ?, duration_seconds = ?
                WHERE id = ?
            """,
                (datetime.now(timezone.utc), "failed", duration, run_id),
            )

            self.alerts.send(project_id, "execution_error", "high", str(e))

            plugin_manager.dispatch(
                "alert",
                alert={
                    "project_id": project_id,
                    "severity": "high",
                    "message": f"Project {project_id} failed with exception: {e!s}",
                },
            )

            event_bus.publish(
                "project.run.failed",
                {"project_id": project_id, "run_id": run_id, "reason": "exception", "error": str(e)},
                source="orchestrator",
                priority="critical",
            )

            return {"error": str(e), "duration": duration}

    def _update_project_stats(self, project_id: str):
        stats = db.execute_one(
            """
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as success,
                AVG(duration_seconds) as avg_dur
            FROM project_runs
            WHERE project_id = ?
        """,
            (project_id,),
        )

        if stats:
            success_rate = (stats["success"] / stats["total"] * 100) if stats["total"] > 0 else 0
            db.execute_insert(
                """
                UPDATE projects
                SET last_run = ?, run_count = ?, success_rate = ?, avg_duration = ?
                WHERE id = ?
            """,
                (datetime.now(timezone.utc), stats["total"], success_rate, stats["avg_dur"] or 0, project_id),
            )

    def run_batch(self, project_ids: list[str], timeout: int | None = None) -> dict[str, dict]:
        results = {}
        for pid in project_ids:
            results[pid] = self.run_project(pid, timeout)
        return results

    def list_intelligence(self, severity: str | None = None, source: str | None = None, limit: int = 50) -> list[dict]:
        query = "SELECT * FROM intelligence WHERE 1=1"
        params: list[str | int] = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if source:
            query += " AND source_project = ?"
            params.append(source)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = db.execute(query, tuple(params))
        return [{**dict(row), "data": json.loads(row["data"]) if row["data"] else {}} for row in rows]

    def get_correlations(self, project_id: str) -> list[dict]:
        rows = db.execute(
            """
            SELECT source_project, intel_type, severity, data, created_at
            FROM intelligence
            WHERE related_projects LIKE ?
            ORDER BY created_at DESC LIMIT 20
        """,
            (f"%{project_id}%",),
        )

        return [
            {
                "source": row["source_project"],
                "type": row["intel_type"],
                "severity": row["severity"],
                "data": json.loads(row["data"]) if row["data"] else {},
                "time": row["created_at"],
            }
            for row in rows
        ]

    def get_threat_score(self) -> dict[str, Any]:
        scores = self.intel.threat_scores
        return {
            "aggregate": sum(scores.values()),
            "breakdown": dict(sorted(scores.items(), key=lambda x: -x[1])[:10]),
            "level": self._threat_level(sum(scores.values())),
        }

    def _threat_level(self, score: float) -> str:
        if score >= 50:
            return "critical"
        if score >= 20:
            return "high"
        if score >= 5:
            return "medium"
        return "low"

    def list_alerts(self, sent: bool | None = None, severity: str | None = None, limit: int = 50) -> list[dict]:
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list[str | int] = []

        if sent is not None:
            query += " AND sent = ?"
            params.append(1 if sent else 0)
        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = db.execute(query, tuple(params))
        return [dict(row) for row in rows]

    def acknowledge_alert(self, alert_id: int) -> bool:
        result = db.execute_insert(
            """
            UPDATE alerts SET sent = 1 WHERE id = ?
        """,
            (alert_id,),
        )
        return result > 0

    def get_metrics(
        self, project_id: str | None = None, metric_name: str | None = None, limit: int = 100
    ) -> list[dict]:
        query = "SELECT * FROM metrics WHERE 1=1"
        params: list[str | int] = []

        if project_id:
            query += " AND project_id = ?"
            params.append(project_id)
        if metric_name:
            query += " AND metric_name = ?"
            params.append(metric_name)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = db.execute(query, tuple(params))
        return [{**dict(row), "labels": json.loads(row["labels"]) if row["labels"] else {}} for row in rows]

    def get_health_checks(self) -> list[dict]:
        checks = []

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
        except Exception as e:
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
        except Exception as e:
            checks.append(
                {
                    "component": "disk_space",
                    "status": "unknown",
                    "message": str(e),
                    "latency_ms": 0,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )

        project_count = len(self.registry)
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

        import smtplib

        start = time.time()
        try:
            if settings.alerts.email_smtp_host:
                with smtplib.SMTP(
                    settings.alerts.email_smtp_host, settings.alerts.email_smtp_port, timeout=5
                ) as server:
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
        except Exception as e:
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

    def generate_summary_report(self) -> str:
        status = self.get_status()

        report = f"""
╔══════════════════════════════════════════════════════════════════╗
║     PicoShogun Command Centre Report                  ║
╚══════════════════════════════════════════════════════════════════╝

Generated: {status["timestamp"]}
System Health: {status["system_health"].upper()}
Uptime: {status["uptime_seconds"]:.0f} seconds

OVERALL STATUS
──────────────
Projects:      {status["projects_total"]} total
Active Runs:   {status["projects_active"]}
Failed (24h):  {status["projects_failed"]}
Threat Level:  {status["threat_score"]:.1f}/100
Active Intel:  {status["active_threats"]} critical/high items
Pending Alerts: {status["pending_alerts"]}

THREAT SCORE BREAKDOWN
──────────────────────
"""
        for pid, score in sorted(self.intel.threat_scores.items(), key=lambda x: -x[1])[:10]:
            report += f"  {pid}: {score:.1f}\n"

        return report

    def generate_project_report(self, project_id: str) -> dict[str, Any] | None:
        project = self.get_project(project_id)
        if not project:
            return None

        runs = db.execute(
            """
            SELECT * FROM project_runs
            WHERE project_id = ?
            ORDER BY run_start DESC LIMIT 10
        """,
            (project_id,),
        )

        intel = db.execute(
            """
            SELECT * FROM intelligence
            WHERE source_project = ?
            ORDER BY created_at DESC LIMIT 10
        """,
            (project_id,),
        )

        return {
            "project": project,
            "recent_runs": [dict(r) for r in runs],
            "intelligence": [dict(r) for r in intel],
            "correlations": self.get_correlations(project_id),
        }


orchestrator = EnhancedOrchestrator()
