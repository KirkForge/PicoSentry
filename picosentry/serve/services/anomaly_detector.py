import json
import logging
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar, cast

from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.services.metrics import metrics

try:
    import psycopg2
except ImportError:
    psycopg2 = cast("Any", None)


# Expected DB-related exceptions that the detector catches at read boundaries so
# a transient database problem does not crash the background loop or the API
# caller, while unexpected programmer errors still propagate.
_DB_BOUNDARY_ERRORS: tuple[type[BaseException], ...] = (
    sqlite3.Error,
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
)
if psycopg2 is not None:
    _DB_BOUNDARY_ERRORS = (*_DB_BOUNDARY_ERRORS, psycopg2.Error)

# Expected exceptions inside the background check cycle.  Programmer errors
# such as NameError or AssertionError should propagate so the thread dies and
# the bug is noticed instead of being silently swallowed every 60 seconds.
_CYCLE_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
)

logger = logging.getLogger("picoshogun.Anomaly")

CONFIG_PATH = Path(__file__).parent.parent / "config" / "anomaly_rules.json"

DEFAULT_RULES = [
    {
        "id": "high_error_rate",
        "metric_name": "api_requests_total",
        "labels": {"status_class": "5xx"},
        "threshold": 10,
        "comparison": "gt",
        "duration_seconds": 300,
        "alert_channel": "all",
        "description": "Error rate > 10 in 5 minutes",
    },
    {
        "id": "high_latency",
        "metric_name": "api_request_duration_seconds",
        "threshold": 5.0,
        "comparison": "gt",
        "duration_seconds": 60,
        "alert_channel": "all",
        "description": "API latency > 5s sustained for 1 minute",
    },
    {
        "id": "disk_space_low",
        "metric_name": "disk_used_pct",
        "threshold": 85,
        "comparison": "gt",
        "duration_seconds": 0,
        "alert_channel": "all",
        "description": "Disk usage > 85%",
    },
    {
        "id": "project_failures",
        "metric_name": "project_failures_total",
        "threshold": 5,
        "comparison": "gt",
        "duration_seconds": 600,
        "alert_channel": "all",
        "description": "More than 5 project failures in 10 minutes",
    },
    {
        "id": "health_degraded",
        "metric_name": "health_status",
        "threshold": 1,
        "comparison": "gte",
        "duration_seconds": 0,
        "alert_channel": "all",
        "description": "Any health check shows warning or critical status",
    },
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
    org_id: str | None = None


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
    org_id: str | None = None
    alert_channel: str = "all"


class AnomalyDetector:
    """Monitors metrics against configurable rules and fires alerts when thresholds are breached."""

    def __init__(self, db: DatabaseManager, alert_hub=None):
        self.db = db
        self.alert_hub = alert_hub
        self.rules: list[AnomalyRule] = []
        self.alert_history: list[AnomalyAlert] = []
        self._running = False
        self._thread: threading.Thread | None = None
        self._check_interval = 60  # seconds
        self._lock = threading.RLock()
        # rule_id -> monotonic time the current breach was first seen;
        # feeds the sustained-breach gate in check_rules.
        self._breach_since: dict[str, float] = {}
        self._load_rules()

    def _load_rules(self):
        loaded_rules: list[AnomalyRule] = []
        if CONFIG_PATH.exists():
            try:
                with CONFIG_PATH.open() as f:
                    rule_dicts = json.load(f)
                loaded_rules = [
                    AnomalyRule(
                        id=r["id"],
                        metric_name=r["metric_name"],
                        threshold=r["threshold"],
                        comparison=r.get("comparison", "gt"),
                        duration_seconds=r.get("duration_seconds", 0),
                        alert_channel=r.get("alert_channel", "all"),
                        description=r.get("description", ""),
                        labels=r.get("labels", {}),
                        enabled=r.get("enabled", True),
                    )
                    for r in rule_dicts
                ]
            except (json.JSONDecodeError, OSError, ValueError, TypeError):
                logger.warning("Failed to load anomaly rules from %s", CONFIG_PATH, exc_info=True)

        if not loaded_rules:
            CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with CONFIG_PATH.open("w") as f:
                json.dump(DEFAULT_RULES, f, indent=2)
            loaded_rules = [
                AnomalyRule(
                    id=r["id"],
                    metric_name=r["metric_name"],
                    threshold=r["threshold"],
                    comparison=r.get("comparison", "gt"),
                    duration_seconds=r.get("duration_seconds", 0),
                    alert_channel=r.get("alert_channel", "all"),
                    description=r.get("description", ""),
                    labels=r.get("labels", {}),
                    enabled=r.get("enabled", True),
                )
                for r in DEFAULT_RULES
            ]

        with self._lock:
            self.rules = loaded_rules

    def _compare(self, value: float, threshold: float, comparison: str) -> bool:
        ops = {
            "gt": lambda v, t: v > t,
            "gte": lambda v, t: v >= t,
            "lt": lambda v, t: v < t,
            "lte": lambda v, t: v <= t,
            "eq": lambda v, t: abs(v - t) < 0.001,
        }
        return ops.get(comparison, ops["gt"])(value, threshold)

    def _rule_samples(self, rule: AnomalyRule) -> list:
        """Metric samples for *rule*, label-filtered; empty when unrecorded."""
        with metrics._lock:
            metric_list = metrics.metrics.get(rule.metric_name, [])
            if rule.labels:
                return [m for m in metric_list if all(m.labels.get(k) == v for k, v in rule.labels.items())]
            return list(metric_list)

    def _evaluate_rule(self, rule: AnomalyRule) -> tuple[float | None, bool]:
        """Return (value, windowed).

        Counter rules with a duration consume it as the delta window: the
        samples carry the cumulative value at their timestamp, so
        last-inside-window minus last-before-window is exactly "events in
        the trailing N seconds" — the semantics rule descriptions promise
        ("…in 5 minutes"). With no pre-window sample the series began
        inside the window, so the latest cumulative value IS the delta.

        Everything else (gauges, histograms, health_status) reads the
        latest value; duration_seconds there means sustained-breach time,
        gated in check_rules.
        """
        if rule.metric_name == "health_status":
            return self._get_health_value(), False

        samples = self._rule_samples(rule)
        if not samples:
            return None, False

        if samples[-1].metric_type == "counter" and rule.duration_seconds > 0:
            cutoff = time.time() - rule.duration_seconds
            last_in_window = next((m for m in reversed(samples) if m.timestamp >= cutoff), None)
            if last_in_window is None:
                return 0.0, True
            last_before = next((m for m in reversed(samples) if m.timestamp < cutoff), None)
            if last_before is None:
                return last_in_window.value, True
            return last_in_window.value - last_before.value, True

        return samples[-1].value, False

    def _clear_breach(self, rule_id: str) -> None:
        with self._lock:
            self._breach_since.pop(rule_id, None)

    def _breach_persisted(self, rule_id: str, duration_seconds: int) -> bool:
        """True once the condition has held for duration_seconds.

        Granularity is the check cycle interval (_check_interval): a rule
        asking for 90s of persistence with a 60s cycle fires on the second
        consecutive breach, i.e. somewhere in (60s, 120s].
        """
        with self._lock:
            first = self._breach_since.setdefault(rule_id, time.monotonic())
        return time.monotonic() - first >= duration_seconds

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
                component, status = r["component"], r["status"]
                if component not in latest_by_component:
                    latest_by_component[component] = status

            statuses = list(latest_by_component.values())
            if any(s == "critical" for s in statuses):
                return 2.0
            # Only real probe results count as warnings: "disabled"
            # (unconfigured SMTP) and "unknown" (statvfs failed) must not
            # fire health_degraded every cycle forever.
            if any(s in ("warning", "degraded") for s in statuses):
                return 1.0
            return 0.0
        except _DB_BOUNDARY_ERRORS:
            logger.warning("Health value lookup failed; using neutral health score", exc_info=True)
            return 0.0

    def check_rules(self) -> list[AnomalyAlert]:
        with self._lock:
            rules_snapshot = list(self.rules)

        alerts = []
        for rule in rules_snapshot:
            if not rule.enabled:
                continue

            value, windowed = self._evaluate_rule(rule)

            if value is None:
                self._clear_breach(rule.id)
                continue

            if not self._compare(value, rule.threshold, rule.comparison):
                self._clear_breach(rule.id)
                continue

            if not windowed and rule.duration_seconds > 0:
                if not self._breach_persisted(rule.id, rule.duration_seconds):
                    continue
            else:
                self._clear_breach(rule.id)

            severity = "critical" if rule.comparison in ("gt", "gte") and value > rule.threshold * 1.5 else "warning"
            alert = AnomalyAlert(
                rule_id=rule.id,
                metric_name=rule.metric_name,
                value=value,
                threshold=rule.threshold,
                comparison=rule.comparison,
                timestamp=datetime.now(timezone.utc).isoformat(),
                description=rule.description,
                severity=severity,
                alert_channel=rule.alert_channel,
            )
            alerts.append(alert)

        return alerts

    _CHANNEL_MAP: ClassVar[dict[str, list[str]]] = {
        "email": ["email"],
        "discord": ["discord"],
        "slack": ["slack"],
        "syslog": ["syslog"],
    }

    def _channels_for(self, alert_channel: str) -> list[str] | None:
        """Alert-hub channels for a rule's alert_channel setting.

        None means the hub's configured defaults. "all" and "webhook" both
        map there — the hub has no standalone webhook channel; its discord/
        slack/email deliveries *are* the configured webhook set.
        """
        return self._CHANNEL_MAP.get(alert_channel)

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
                channels=self._channels_for(alert.alert_channel),
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
                    alert.rule_id,
                    alert.metric_name,
                    alert.value,
                    alert.threshold,
                    alert.comparison,
                    alert.severity,
                    alert.description,
                    alert.timestamp,
                ),
            )
        except _DB_BOUNDARY_ERRORS:
            logger.warning("anomaly_alerts table missing; creating schema", exc_info=True)
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
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    org_id TEXT
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
                    alert.rule_id,
                    alert.metric_name,
                    alert.value,
                    alert.threshold,
                    alert.comparison,
                    alert.severity,
                    alert.description,
                    alert.timestamp,
                ),
            )

        with self._lock:
            self.alert_history.append(alert)
            # Evict old alerts to prevent unbounded memory growth
            if len(self.alert_history) > 1000:
                self.alert_history = self.alert_history[-500:]

    def _run_check_cycle(self):
        alerts = self.check_rules()
        for alert in alerts:
            with self._lock:
                recent = [
                    a
                    for a in self.alert_history
                    if a.rule_id == alert.rule_id
                    and (datetime.now(timezone.utc) - datetime.fromisoformat(a.timestamp)).total_seconds() < 300
                ]
            if not recent:
                self._fire_alert(alert)

    def _background_loop(self):
        while self._running:
            try:
                self._run_check_cycle()
            except _CYCLE_ERRORS:
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

    def get_alerts(self, limit: int = 50, org_id: str | None = None) -> list[dict[str, Any]]:
        try:
            # Org filter belongs in SQL: a global LIMIT filtered in Python
            # starved quieter orgs whenever a busy tenant filled the window.
            if org_id is None:
                rows = self.db.execute(
                    """
                    SELECT rule_id, metric_name, value, threshold, comparison, severity, description, created_at, org_id
                    FROM anomaly_alerts
                    ORDER BY created_at DESC
                    LIMIT ?
                """,
                    (limit,),
                )
            else:
                rows = self.db.execute(
                    """
                    SELECT rule_id, metric_name, value, threshold, comparison, severity, description, created_at, org_id
                    FROM anomaly_alerts
                    WHERE org_id IS NULL OR org_id = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                """,
                    (org_id, limit),
                )
            return [
                {
                    "rule_id": r["rule_id"],
                    "metric_name": r["metric_name"],
                    "value": r["value"],
                    "threshold": r["threshold"],
                    "comparison": r["comparison"],
                    "severity": r["severity"],
                    "description": r["description"],
                    "timestamp": r["created_at"],
                    "org_id": r["org_id"],
                }
                for r in rows
            ]
        except _DB_BOUNDARY_ERRORS:
            logger.warning("Failed to load anomaly alerts; returning empty list", exc_info=True)
            return []

    def get_rules(self, org_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            rules_snapshot = [asdict(r) for r in self.rules]
        if org_id is not None:
            rules_snapshot = [r for r in rules_snapshot if r.get("org_id") is None or r.get("org_id") == org_id]
        return rules_snapshot

    def update_rule(self, rule_id: str, **kwargs) -> bool:
        with self._lock:
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
        with self._lock:
            rules_data = [asdict(r) for r in self.rules]
        with CONFIG_PATH.open("w") as f:
            json.dump(rules_data, f, indent=2)
