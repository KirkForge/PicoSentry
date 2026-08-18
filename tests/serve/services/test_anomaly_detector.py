"""Unit tests for the anomaly detector exception-handling paths."""

from __future__ import annotations

import logging

import pytest

from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.services.anomaly_detector import AnomalyDetector, AnomalyRule


class TestAnomalyDetectorHardening:
    """Anomaly detector must log swallowed failures instead of hiding them."""

    def test_malformed_rules_file_logs_and_falls_back(self, tmp_path, caplog, monkeypatch):
        import picosentry.serve.services.anomaly_detector as ad_mod

        bad_path = tmp_path / "bad_rules.json"
        bad_path.write_text("not json", encoding="utf-8")
        monkeypatch.setattr(ad_mod, "CONFIG_PATH", bad_path)

        db = DatabaseManager(db_path=tmp_path / "anomaly.db", backend="sqlite")
        with caplog.at_level(logging.WARNING, logger="picoshogun.Anomaly"):
            detector = AnomalyDetector(db=db)

        assert detector.rules  # falls back to DEFAULT_RULES
        assert any("Failed to load anomaly rules" in r.message for r in caplog.records)

    def test_health_value_db_failure_is_logged(self, tmp_path, caplog, monkeypatch):
        db = DatabaseManager(db_path=tmp_path / "anomaly.db", backend="sqlite")
        detector = AnomalyDetector(db=db)

        def _boom(*args, **kwargs):
            raise RuntimeError("db down")

        with caplog.at_level(logging.WARNING, logger="picoshogun.Anomaly"):
            monkeypatch.setattr(db, "execute", _boom)
            value = detector._get_health_value()

        assert value == 0.0
        assert any("Health value lookup failed" in r.message for r in caplog.records)

    def test_get_alerts_db_failure_is_logged(self, tmp_path, caplog, monkeypatch):
        db = DatabaseManager(db_path=tmp_path / "anomaly.db", backend="sqlite")
        detector = AnomalyDetector(db=db)

        def _boom(*args, **kwargs):
            raise RuntimeError("db down")

        with caplog.at_level(logging.WARNING, logger="picoshogun.Anomaly"):
            monkeypatch.setattr(db, "execute", _boom)
            alerts = detector.get_alerts()

        assert alerts == []
        assert any("Failed to load anomaly alerts" in r.message for r in caplog.records)

    def test_health_value_unexpected_error_propagates(self, tmp_path, monkeypatch):
        db = DatabaseManager(db_path=tmp_path / "anomaly.db", backend="sqlite")
        detector = AnomalyDetector(db=db)

        def _boom(*args, **kwargs):
            raise NameError("programmer mistake")

        monkeypatch.setattr(db, "execute", _boom)
        with pytest.raises(NameError, match="programmer mistake"):
            detector._get_health_value()

    def test_get_alerts_unexpected_error_propagates(self, tmp_path, monkeypatch):
        db = DatabaseManager(db_path=tmp_path / "anomaly.db", backend="sqlite")
        detector = AnomalyDetector(db=db)

        def _boom(*args, **kwargs):
            raise NameError("programmer mistake")

        monkeypatch.setattr(db, "execute", _boom)
        with pytest.raises(NameError, match="programmer mistake"):
            detector.get_alerts()

    def test_fire_alert_unexpected_error_propagates(self, tmp_path, monkeypatch):
        from picosentry.serve.services.anomaly_detector import AnomalyAlert

        db = DatabaseManager(db_path=tmp_path / "anomaly.db", backend="sqlite")
        detector = AnomalyDetector(db=db)

        def _boom(*args, **kwargs):
            raise NameError("programmer mistake")

        monkeypatch.setattr(db, "execute_insert", _boom)
        alert = AnomalyAlert(
            rule_id="test",
            metric_name="health_status",
            value=1.0,
            threshold=1.0,
            comparison="gte",
            timestamp="2026-07-02T00:00:00+00:00",
            description="test",
            severity="warning",
        )
        with pytest.raises(NameError, match="programmer mistake"):
            detector._fire_alert(alert)

    def test_background_cycle_expected_error_is_logged(self, tmp_path, caplog, monkeypatch):
        db = DatabaseManager(db_path=tmp_path / "anomaly.db", backend="sqlite")
        detector = AnomalyDetector(db=db)

        def _boom(*args, **kwargs):
            raise RuntimeError("cycle problem")

        monkeypatch.setattr(detector, "_run_check_cycle", _boom)
        detector._running = True

        def _break_after_one(*args, **kwargs):
            detector._running = False

        monkeypatch.setattr("time.sleep", _break_after_one)

        with caplog.at_level(logging.ERROR, logger="picoshogun.Anomaly"):
            detector._background_loop()

        assert any("Anomaly detection cycle failed" in r.message for r in caplog.records)

    def test_background_cycle_unexpected_error_propagates(self, tmp_path, monkeypatch):
        db = DatabaseManager(db_path=tmp_path / "anomaly.db", backend="sqlite")
        detector = AnomalyDetector(db=db)

        def _boom(*args, **kwargs):
            raise NameError("programmer mistake")

        monkeypatch.setattr(detector, "_run_check_cycle", _boom)
        detector._running = True

        def _break_after_one(*args, **kwargs):
            detector._running = False

        monkeypatch.setattr("time.sleep", _break_after_one)

        with pytest.raises(NameError, match="programmer mistake"):
            detector._background_loop()


class TestRuleThresholdBounds:
    """Router validation must accept the thresholds shipped rules actually use."""

    def test_thresholds_above_one_are_accepted(self):

        from picosentry.serve.api.routers.anomaly import AnomalyRuleUpdateRequest

        assert AnomalyRuleUpdateRequest(threshold=85.0).threshold == 85.0
        assert AnomalyRuleUpdateRequest(threshold=1e9).threshold == 1e9

    def test_negative_threshold_still_rejected(self):
        from pydantic import ValidationError

        from picosentry.serve.api.routers.anomaly import AnomalyRuleUpdateRequest

        with pytest.raises(ValidationError):
            AnomalyRuleUpdateRequest(threshold=-0.1)

    def test_every_shipped_rule_threshold_is_valid(self):

        from picosentry.serve.api.routers.anomaly import AnomalyRuleUpdateRequest
        from picosentry.serve.services.anomaly_detector import DEFAULT_RULES

        for rule in DEFAULT_RULES:  # shipped rules use 5/10/85 — raw values, not ratios
            AnomalyRuleUpdateRequest(threshold=rule["threshold"])


class TestRuleSemantics:
    """WO-012: rules must mean what their descriptions say.

    Counters evaluate as a windowed delta (">10 in 5 minutes"), not the
    lifetime cumulative; gauges/histograms with a duration gate on
    sustained breach; alert_channel routes to the configured hub channel.
    """

    @staticmethod
    def _fresh_detector(tmp_path):
        db = DatabaseManager(db_path=tmp_path / "anomaly.db", backend="sqlite")
        return AnomalyDetector(db=db)

    @staticmethod
    def _clear_metrics():
        from picosentry.serve.services.metrics import metrics

        with metrics._lock:
            metrics.metrics.clear()
            metrics.counters.clear()
            metrics._counter_timestamps.clear()

    def setup_method(self):
        self._clear_metrics()

    def test_counter_rule_uses_window_delta_not_cumulative(self, tmp_path):
        import time as time_mod

        from picosentry.serve.services.metrics import Metric, metrics

        detector = self._fresh_detector(tmp_path)
        rule = AnomalyRule(
            id="err_burst",
            metric_name="api_requests_total",
            threshold=10,
            comparison="gt",
            duration_seconds=300,
            alert_channel="all",
            description=">10 in 5 minutes",
            labels={"status_class": "5xx"},
        )
        detector.rules = [rule]

        # A busy pre-window history (cumulative 100 at t-600s) must NOT
        # count toward the window: only the 11 fresh 5xx samples do.
        old = Metric(
            name="api_requests_total",
            value=100.0,
            labels={"status_class": "5xx"},
            timestamp=time_mod.time() - 600,
            metric_type="counter",
        )
        metrics.metrics["api_requests_total"].append(old)
        for i in range(101, 112):  # cumulative 101..111, all "now"
            metrics.metrics["api_requests_total"].append(
                Metric(
                    name="api_requests_total",
                    value=float(i),
                    labels={"status_class": "5xx"},
                    timestamp=time_mod.time(),
                    metric_type="counter",
                )
            )

        value, windowed = detector._evaluate_rule(rule)
        assert windowed
        assert value == 11, f"window delta should be 11, got {value}"
        alerts = detector.check_rules()
        assert [a.rule_id for a in alerts] == ["err_burst"]

    def test_old_burst_outside_window_does_not_fire(self, tmp_path):
        import time as time_mod

        from picosentry.serve.services.metrics import Metric, metrics

        detector = self._fresh_detector(tmp_path)
        rule = AnomalyRule(
            id="err_old",
            metric_name="api_requests_total",
            threshold=10,
            comparison="gt",
            duration_seconds=300,
            alert_channel="all",
            description=">10 in 5 minutes",
            labels={"status_class": "5xx"},
        )
        detector.rules = [rule]
        for i in range(1, 51):  # 50 errors — but all 10 minutes ago
            metrics.metrics["api_requests_total"].append(
                Metric(
                    name="api_requests_total",
                    value=float(i),
                    labels={"status_class": "5xx"},
                    timestamp=time_mod.time() - 600,
                    metric_type="counter",
                )
            )

        value, _ = detector._evaluate_rule(rule)
        assert value == 0, "stale samples must not satisfy the window"
        assert detector.check_rules() == []

    def test_gauge_breach_requires_sustained_duration(self, tmp_path, monkeypatch):
        import picosentry.serve.services.anomaly_detector as ad_mod
        from picosentry.serve.services.metrics import metrics

        detector = self._fresh_detector(tmp_path)
        rule = AnomalyRule(
            id="disk_hot",
            metric_name="disk_used_pct",
            threshold=85,
            comparison="gt",
            duration_seconds=60,
            alert_channel="syslog",
            description="sustained > 85%",
        )
        detector.rules = [rule]

        clock = [1000.0]
        monkeypatch.setattr(ad_mod.time, "monotonic", lambda: clock[0])
        metrics.gauge("disk_used_pct", 90)

        assert detector.check_rules() == [], "fired before the sustained duration elapsed"
        clock[0] += 61
        alerts = detector.check_rules()
        assert [a.rule_id for a in alerts] == ["disk_hot"]

        # Recovery clears the persistence timer: a new breach starts over.
        metrics.gauge("disk_used_pct", 10)
        assert detector.check_rules() == []
        clock[0] += 61
        metrics.gauge("disk_used_pct", 90)
        assert detector.check_rules() == [], "breach timer was not reset by recovery"

    def test_alert_channel_routes_to_hub_channels(self, tmp_path):
        detector = self._fresh_detector(tmp_path)
        assert detector._channels_for("all") is None  # hub defaults
        assert detector._channels_for("webhook") is None  # hub defaults (discord/slack ARE webhooks)
        assert detector._channels_for("email") == ["email"]
        assert detector._channels_for("discord") == ["discord"]
        assert detector._channels_for("slack") == ["slack"]
        assert detector._channels_for("syslog") == ["syslog"]

    def test_fire_alert_passes_rule_channel_to_hub(self, tmp_path):
        from picosentry.serve.services.anomaly_detector import AnomalyAlert

        detector = self._fresh_detector(tmp_path)

        class _Hub:
            def __init__(self):
                self.sent: list[dict] = []

            def send(self, **kwargs):
                self.sent.append(kwargs)

        hub = _Hub()
        detector.alert_hub = hub
        alert = AnomalyAlert(
            rule_id="r",
            metric_name="m",
            value=1.0,
            threshold=1.0,
            comparison="gt",
            timestamp="2026-08-17T00:00:00+00:00",
            description="d",
            alert_channel="email",
        )
        detector._fire_alert(alert)
        assert hub.sent and hub.sent[0]["channels"] == ["email"]

    def test_shipped_high_error_rate_rule_fires_from_live_5xx_traffic(self, client, monkeypatch, tmp_path):
        """End-to-end label pipeline: 503 responses recorded by the audit
        middleware satisfy the shipped high_error_rate rule (status_class
        5xx) — the exact wiring that was dead before WO-012."""
        from picosentry.serve.database.manager import db as app_db

        def _failing_execute_one(*_a, **_kw):
            raise OSError("database is down")

        # /health/ready turns this into a 503; the middleware records it.
        monkeypatch.setattr(app_db, "execute_one", _failing_execute_one)
        for _ in range(11):
            assert client.get("/health/ready").status_code == 503
        monkeypatch.undo()

        detector = self._fresh_detector(tmp_path)
        rule = next(r for r in detector.rules if r.id == "high_error_rate")
        assert rule.labels.get("status_class") == "5xx"
        value, windowed = detector._evaluate_rule(rule)
        assert windowed
        assert value >= 11, f"middleware 503s not visible to the rule (value={value})"


class TestHealthValueSemantics:
    """WO5.0.0-021: only real probe results count as warnings.

    "disabled" (unconfigured SMTP) and "unknown" (statvfs failed) must not
    fire health_degraded every cycle once the SMTP check is persisted."""

    @staticmethod
    def _insert(db, component: str, status: str):
        db.execute_insert(
            "INSERT INTO health_checks (component, status, message, latency_ms) VALUES (?, ?, 'x', 0)",
            (component, status),
        )

    def test_disabled_and_unknown_are_not_warnings(self, tmp_path):
        db = DatabaseManager(db_path=tmp_path / "hv-disabled.db")
        detector = AnomalyDetector(db=db)
        self._insert(db, "database", "healthy")
        self._insert(db, "smtp", "disabled")
        self._insert(db, "disk_space", "unknown")
        assert detector._get_health_value() == 0.0

    def test_warning_counts(self, tmp_path):
        db = DatabaseManager(db_path=tmp_path / "hv-warning.db")
        detector = AnomalyDetector(db=db)
        self._insert(db, "disk_space", "warning")
        assert detector._get_health_value() == 1.0

    def test_critical_counts(self, tmp_path):
        db = DatabaseManager(db_path=tmp_path / "hv-critical.db")
        detector = AnomalyDetector(db=db)
        self._insert(db, "smtp", "critical")
        assert detector._get_health_value() == 2.0


class TestAnomalyAlertsSqlOrgFilter:
    """WO5.0.0-022: the org filter belongs in SQL, not Python after LIMIT.

    A busy org filling the global LIMIT window starved every other org."""

    @staticmethod
    def _insert(db, rule_id: str, org_id: str | None, created_at: str):
        db.execute_insert(
            """
            INSERT INTO anomaly_alerts (rule_id, metric_name, value, threshold, comparison,
                                        severity, description, created_at, org_id)
            VALUES (?, 'm', 1, 1, 'gt', 'warning', 'desc', ?, ?)
            """,
            (rule_id, created_at, org_id),
        )

    def test_busy_org_does_not_starve_quiet_org(self, tmp_path):
        db = DatabaseManager(db_path=tmp_path / "anomaly-org.db")
        detector = AnomalyDetector(db=db)
        for i in range(60):  # more than the default limit of 50
            self._insert(db, "busy_rule", "999", f"2026-01-01 00:{i:02d}:00")
        self._insert(db, "quiet_rule", "7", "2026-01-01 01:00:00")

        rows = detector.get_alerts(limit=50, org_id="7")
        assert [r["rule_id"] for r in rows] == ["quiet_rule"]

    def test_global_alert_rows_visible_to_org_filter(self, tmp_path):
        db = DatabaseManager(db_path=tmp_path / "anomaly-global.db")
        detector = AnomalyDetector(db=db)
        self._insert(db, "global_rule", None, "2026-01-01 00:00:00")
        self._insert(db, "other_org_rule", "999", "2026-01-01 00:01:00")

        rows = detector.get_alerts(limit=50, org_id="7")
        assert [r["rule_id"] for r in rows] == ["global_rule"]

    def test_no_org_filter_returns_everything(self, tmp_path):
        db = DatabaseManager(db_path=tmp_path / "anomaly-nofilter.db")
        detector = AnomalyDetector(db=db)
        self._insert(db, "global_rule", None, "2026-01-01 00:00:00")
        self._insert(db, "org_rule", "7", "2026-01-01 00:01:00")

        rows = detector.get_alerts(limit=50)
        assert {r["rule_id"] for r in rows} == {"global_rule", "org_rule"}
