
import json
import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.services.metrics import metrics

logger = logging.getLogger("picoshogun.Anomaly")

CONFIG_PATH = Path(__file__).parent.parent / "config" / "anomaly_rules.json"

DEFAULT_RULES = [
    {
        "id": "high_error_rate",
        "metric_name": "api_requests_total",
        "labels": {"status": "5xx"},
        "threshold": 10,
        "comparison": "gt",
        "duration_seconds": 300,
        "alert_channel": "all",
        "description": "Error rate > 10 in 5 minutes"
    },
    {
        "id": "high_latency",
        "metric_name": "api_request_duration_seconds",
        "threshold": 5.0,
        "comparison": "gt",
        "duration_seconds": 60,
        "alert_channel": "all",
        "description": "API latency > 5s sustained for 1 minute"
    },
    {
        "id": "disk_space_low",
        "metric_name": "disk_used_pct",
        "threshold": 85,
        "comparison": "gt",
        "duration_seconds": 0,
        "alert_channel": "all",
        "description": "Disk usage > 85%"
    },
    {
        "id": "project_failures",
        "metric_name": "project_failures_total",
        "threshold": 5,
        "comparison": "gt",
        "duration_seconds": 600,
        "alert_channel": "all",
        "description": "More than 5 project failures in 10 minutes"
    },
    {
        "id": "health_degraded",
        "metric_name": "health_status",
        "threshold": 1,
        "comparison": "gte",
        "duration_seconds": 0,
        "alert_channel": "all",
        "description": "Any health check shows warning or critical status"
    }
]


@dataclass
class AnomalyRule:
    id: str
    metric_name: str
    threshold: float
    comparison: str  # gt, gte, lt, lte, eq
    duration_seconds: int  # how long the condition must persist
    alert_channel: str  # all, email, discord, webhook
    description: str
    labels: dict[str, str] = field(default_factory=dict)
    enabled: bool = True


@dataclass
class AnomalyAlert:
    rule_id: str
    metric_name: str
    value: float
    threshold: float
    comparison: str
    timestamp: str
    description: str
    severity: str = "warning"  # warning, critical


class AnomalyDetector:

    def __init__(self, db: DatabaseManager, alert_hub=None):
        self.db = db
        self.alert_hub = alert_hub
        self.rules: list[AnomalyRule] = []
        self.alert_history: list[AnomalyAlert] = []
        self._running = False
        self._thread: threading.Thread | None = None
        self._check_interval = 60  # seconds
        self._load_rules()

    def _load_rules(self):
        if CONFIG_PATH.exists():
            try:
                with open(CONFIG_PATH) as f:
                    rule_dicts = json.load(f)
                self.rules = [
                    AnomalyRule(
                        id=r["id"],
                        metric_name=r["metric_name"],
                        threshold=r["threshold"],
                        comparison=r.get("comparison", "gt"),
                        duration_seconds=r.get("duration_seconds", 0),
                        alert_channel=r.get("alert_channel", "all"),
                        description=r.get("description", ""),
                        labels=r.get("labels", {}),
                        enabled=r.get("enabled", True)
                    )
                    for r in rule_dicts
                ]
                return
            except Exception:
                pass


        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(DEFAULT_RULES, f, indent=2)
        self.rules = [
            AnomalyRule(
                id=r["id"],
                metric_name=r["metric_name"],
                threshold=r["threshold"],
                comparison=r.get("comparison", "gt"),
                duration_seconds=r.get("duration_seconds", 0),
                alert_channel=r.get("alert_channel", "all"),
                description=r.get("description", ""),
                labels=r.get("labels", {}),
                enabled=r.get("enabled", True)
            )
            for r in DEFAULT_RULES
        ]

    def _compare(self, value: float, threshold: float, comparison: str) -> bool:
        ops = {
            "gt": lambda v, t: v > t,
            "gte": lambda v, t: v >= t,
            "lt": lambda v, t: v < t,
            "lte": lambda v, t: v <= t,
            "eq": lambda v, t: abs(v - t) < 0.001,
        }
        return ops.get(comparison, ops["gt"])(value, threshold)

    def _get_metric_value(self, rule: AnomalyRule) -> float | None:
        with metrics._lock:
            metric_list = metrics.metrics.get(rule.metric_name, [])
            if not metric_list:
                return None


            if rule.labels:
                filtered = [
                    m for m in metric_list
                    if all(m.labels.get(k) == v for k, v in rule.labels.items())
                ]
                if not filtered:
                    return None
                return filtered[-1].value
            return metric_list[-1].value

    def _get_health_value(self) -> float:
        try:
            rows = self.db.execute("""
                SELECT component, status FROM health_checks
                ORDER BY created_at DESC
            """)
            if not rows:
                return 0.0

            latest_by_component: dict[str, str] = {}
            for r in rows:
                component, status = r[0], r[1]
                if component not in latest_by_component:
                    latest_by_component[component] = status

            statuses = list(latest_by_component.values())
            if any(s == "critical" for s in statuses):
                return 2.0
            if any(s in ("warning", "degraded", "disabled") for s in statuses):
                return 1.0
            return 0.0
        except Exception:
            return 0.0

    def check_rules(self) -> list[AnomalyAlert]:
        alerts = []

        for rule in self.rules:
            if not rule.enabled:
                continue


            value = self._get_health_value() if rule.metric_name == "health_status" else self._get_metric_value(rule)

            if value is None:
                continue

            if self._compare(value, rule.threshold, rule.comparison):
                severity = (
                    "critical"
                    if rule.comparison in ("gt", "gte") and value > rule.threshold * 1.5
                    else "warning"
                )
                alert = AnomalyAlert(
                    rule_id=rule.id,
                    metric_name=rule.metric_name,
                    value=value,
                    threshold=rule.threshold,
                    comparison=rule.comparison,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    description=rule.description,
                    severity=severity
                )
                alerts.append(alert)

        return alerts

    def _fire_alert(self, alert: AnomalyAlert):
        if self.alert_hub:
            self.alert_hub.send(
                project_id="system",
                alert_type=f"anomaly_{alert.rule_id}",
                severity=alert.severity,
                message=(
                    f"Rule: {alert.rule_id}\n"
                    f"Metric: {alert.metric_name} = {alert.value}\n"
                    f"Threshold: {alert.comparison} {alert.threshold}\n"
                    f"Severity: {alert.severity}\n"
                    f"Description: {alert.description}"
                ),
                channels=["syslog"]
            )


        try:
            self.db.execute_insert(
                """
                INSERT INTO anomaly_alerts (
                    rule_id, metric_name, value, threshold, comparison, severity, description, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.rule_id, alert.metric_name, alert.value,
                    alert.threshold, alert.comparison, alert.severity,
                    alert.description, alert.timestamp,
                ),
            )
        except Exception:

            self.db.execute("""
                CREATE TABLE IF NOT EXISTS anomaly_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT,
                    metric_name TEXT,
                    value REAL,
                    threshold REAL,
                    comparison TEXT,
                    severity TEXT,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self.db.execute_insert(
                """
                INSERT INTO anomaly_alerts (
                    rule_id, metric_name, value, threshold, comparison, severity, description, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.rule_id, alert.metric_name, alert.value,
                    alert.threshold, alert.comparison, alert.severity,
                    alert.description, alert.timestamp,
                ),
            )

        self.alert_history.append(alert)

    def _run_check_cycle(self):
        alerts = self.check_rules()
        for alert in alerts:

            recent = [a for a in self.alert_history
                       if a.rule_id == alert.rule_id
                       and (datetime.now(timezone.utc) - datetime.fromisoformat(a.timestamp)).total_seconds() < 300]
            if not recent:
                self._fire_alert(alert)

    def _background_loop(self):
        while self._running:
            try:
                self._run_check_cycle()
            except Exception:
                logger.exception("Anomaly detection cycle failed")
            time.sleep(self._check_interval)

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._background_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def get_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        try:
            rows = self.db.execute("""
                SELECT rule_id, metric_name, value, threshold, comparison, severity, description, created_at
                FROM anomaly_alerts
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            return [
                {
                    "rule_id": r[0], "metric_name": r[1], "value": r[2],
                    "threshold": r[3], "comparison": r[4], "severity": r[5],
                    "description": r[6], "timestamp": r[7]
                }
                for r in rows
            ]
        except Exception:
            return []

    def get_rules(self) -> list[dict[str, Any]]:
        return [asdict(r) for r in self.rules]

    def update_rule(self, rule_id: str, **kwargs) -> bool:
        for rule in self.rules:
            if rule.id == rule_id:
                for k, v in kwargs.items():
                    if hasattr(rule, k):
                        setattr(rule, k, v)
                self._save_rules()
                return True
        return False

    def _save_rules(self):
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump([asdict(r) for r in self.rules], f, indent=2)
