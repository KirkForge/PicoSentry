"""Unit tests for the anomaly detector exception-handling paths."""

from __future__ import annotations

import logging

import pytest

from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.services.anomaly_detector import AnomalyDetector


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
