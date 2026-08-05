"""Tests for SLO definitions and tracking."""

from picosentry.sandbox.slo import ALL_SLOS, SLOTracker


class TestSLODefinitions:
    def test_all_slos_have_names(self):
        for slo in ALL_SLOS:
            assert slo.name
            assert slo.target > 0
            assert slo.description

    def test_availability_target(self):
        avail = next(s for s in ALL_SLOS if s.name == "availability")
        assert avail.target == 0.999

    def test_latency_targets(self):
        p50 = next(s for s in ALL_SLOS if s.name == "latency_p50")
        p95 = next(s for s in ALL_SLOS if s.name == "latency_p95")
        p99 = next(s for s in ALL_SLOS if s.name == "latency_p99")
        assert p50.target < p95.target < p99.target

    def test_determinism_target(self):
        det = next(s for s in ALL_SLOS if s.name == "determinism")
        assert det.target == 1.0


class TestSLOTracker:
    def test_record_scan(self):
        tracker = SLOTracker()
        tracker.record_scan(100.0, success=True)
        tracker.record_scan(200.0, success=True)
        tracker.record_scan(50.0, success=False)
        measurements = tracker.measure()
        error_rate = next(m for m in measurements if m.name == "error_rate")
        assert error_rate.measured_value > 0

    def test_health_check_compliance(self):
        tracker = SLOTracker()
        for _ in range(1000):
            tracker.record_health_check(healthy=True)
        tracker.record_health_check(healthy=False)
        measurements = tracker.measure()
        avail = next(m for m in measurements if m.name == "availability")
        assert avail.compliant is True  # 999/1000 = 99.9%

    def test_determinism_compliance(self):
        tracker = SLOTracker()
        for _ in range(100):
            tracker.record_determinism_check(passed=True)
        measurements = tracker.measure()
        det = next(m for m in measurements if m.name == "determinism")
        assert det.compliant is True
        assert det.measured_value == 1.0

    def test_get_report(self):
        tracker = SLOTracker()
        tracker.record_scan(100.0, success=True)
        report = tracker.get_report()
        assert "measurements" in report
        assert "slo_definitions" in report
        assert report["total_scans"] == 1

    def test_negative_duration_handled(self):
        tracker = SLOTracker()
        tracker.record_scan(-50.0, success=True)
        measurements = tracker.measure()
        # Should not crash; latency measurement should still be recorded
        lat = [m for m in measurements if m.name == "latency_p50"]
        assert len(lat) == 1

    def test_zero_measurements_empty_tracker(self):
        tracker = SLOTracker()
        measurements = tracker.measure()
        # No data recorded — no measurements should be produced
        assert measurements == []
        report = tracker.get_report()
        assert report["all_compliant"] is True  # vacuously true

    def test_exactly_99pt9_pct_availability(self):
        tracker = SLOTracker()
        # 999 healthy + 1 unhealthy = exactly 99.9%, which meets the 0.999 target
        for _ in range(999):
            tracker.record_health_check(healthy=True)
        tracker.record_health_check(healthy=False)
        measurements = tracker.measure()
        avail = next(m for m in measurements if m.name == "availability")
        assert avail.measured_value == 0.999
        assert avail.compliant is True  # exactly at threshold is compliant

    def test_non_compliant_below_threshold(self):
        tracker = SLOTracker()
        # 998 healthy + 2 unhealthy = 99.8%, below the 99.9% availability target
        for _ in range(998):
            tracker.record_health_check(healthy=True)
        for _ in range(2):
            tracker.record_health_check(healthy=False)
        measurements = tracker.measure()
        avail = next(m for m in measurements if m.name == "availability")
        assert avail.compliant is False
