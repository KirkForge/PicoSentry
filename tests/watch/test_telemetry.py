"""PicoWatch Telemetry tests."""

from picosentry.watch.telemetry import TelemetryConfig, TelemetrySink
from picosentry.watch.telemetry.metrics import PrometheusMetrics
from picosentry.watch.types import PromptScanResult, ValidationResult


class TestTelemetrySink:
    """Test L7 TelemetrySink."""

    def test_record_prompt_scan(self, tmp_path) -> None:
        """Prompt scan results are recorded to audit log."""
        db_path = tmp_path / "test_audit.db"
        config = TelemetryConfig(audit_db_path=db_path)
        sink = TelemetrySink(config=config)

        result = PromptScanResult(
            blocked=True,
            score=0.94,
            rules_matched=["inj_override_ignore"],
            corpus_hash="abc123",
            corpus_version="1.0",
            duration_ms=2.1,
        )
        sink.record_prompt_scan(result, request_id="req-001")

        # Verify audit log was written
        import sqlite3

        conn = sqlite3.connect(str(db_path))
        rows = conn.execute("SELECT * FROM audit_log").fetchall()
        conn.close()
        assert len(rows) == 1
        assert rows[0][2] == "prompt_scan"  # event_type

    def test_record_validation(self, tmp_path) -> None:
        """Validation results are recorded to audit log."""
        db_path = tmp_path / "test_audit.db"
        config = TelemetryConfig(audit_db_path=db_path)
        sink = TelemetrySink(config=config)

        result = ValidationResult(
            valid=False,
            score=0.95,
            violations=["out_pii_ssn"],
            corpus_hash="abc123",
            corpus_version="1.0",
            duration_ms=1.8,
        )
        sink.record_validation(result, request_id="req-002")

        import sqlite3

        conn = sqlite3.connect(str(db_path))
        rows = conn.execute("SELECT * FROM audit_log").fetchall()
        conn.close()
        assert len(rows) == 1
        assert rows[0][2] == "output_validation"

    def test_prometheus_rendering(self, tmp_path) -> None:
        """Prometheus metrics render correctly."""
        db_path = tmp_path / "test_audit.db"
        config = TelemetryConfig(audit_db_path=db_path)
        sink = TelemetrySink(config=config)

        result = PromptScanResult(
            blocked=True,
            score=0.9,
            rules_matched=["inj_override_ignore"],
            corpus_hash="abc",
            corpus_version="1.0",
            duration_ms=3.0,
        )
        sink.record_prompt_scan(result)

        metrics = sink.render_prometheus()
        assert "picowatch_requests_total" in metrics
        assert "picowatch_prompt_blocked_total" in metrics

    def test_health_status(self, tmp_path) -> None:
        """Health check returns status."""
        db_path = tmp_path / "test_audit.db"
        config = TelemetryConfig(audit_db_path=db_path)
        sink = TelemetrySink(config=config)

        health = sink.health(rules_loaded=25, corpus_hash="abc123", corpus_version="1.0")
        assert health.healthy is True
        assert health.rules_loaded == 25
        assert health.corpus_hash == "abc123"


class TestPrometheusMetrics:
    """Test Prometheus metrics renderer."""

    def test_counter(self) -> None:
        """Counter increments work."""
        metrics = PrometheusMetrics()
        metrics.inc_counter("picowatch_requests_total", labels={"model": "gpt-4"})
        output = metrics.render()
        assert "picowatch_requests_total" in output

    def test_gauge(self) -> None:
        """Gauge set works."""
        metrics = PrometheusMetrics()
        metrics.set_gauge("picowatch_active_scans", 3.0, labels={"guard_type": "prompt"})
        output = metrics.render()
        assert "picowatch_active_scans" in output

    def test_histogram_rendering(self) -> None:
        """Histogram metrics render with buckets, count, and sum."""
        metrics = PrometheusMetrics()
        metrics.observe_histogram("picowatch_scan_duration_seconds", 0.045, labels={"guard_type": "prompt"})
        metrics.observe_histogram("picowatch_scan_duration_seconds", 0.12, labels={"guard_type": "prompt"})
        output = metrics.render()
        assert "# TYPE picowatch_scan_duration_seconds histogram" in output
        assert "picowatch_scan_duration_seconds_count" in output
        assert "picowatch_scan_duration_seconds_sum" in output
        assert 'le="+Inf"' in output

    def test_histogram_no_labels(self) -> None:
        """Histogram without labels renders correctly."""
        metrics = PrometheusMetrics()
        metrics.observe_histogram("picowatch_prompt_score", 0.75)
        output = metrics.render()
        assert "picowatch_prompt_score_count 1" in output
        assert "picowatch_prompt_score_sum" in output
        assert 'picowatch_prompt_score_bucket{le="+Inf"} 1' in output


class TestAuditIntegrity:
    """Test audit log integrity checksums (ADR-008)."""

    def test_checksum_written_to_audit(self, tmp_path) -> None:
        """Audit rows include an HMAC-SHA256 checksum."""
        db_path = tmp_path / "test_integrity.db"
        config = TelemetryConfig(audit_db_path=db_path)
        sink = TelemetrySink(config=config)

        result = PromptScanResult(
            blocked=True,
            score=0.88,
            rules_matched=["inj_override_ignore"],
            corpus_hash="abc456",
            corpus_version="2.0",
            duration_ms=1.5,
        )
        sink.record_prompt_scan(result, request_id="req-integrity-1")

        import sqlite3

        conn = sqlite3.connect(str(db_path))
        rows = conn.execute("SELECT checksum FROM audit_log").fetchall()
        conn.close()
        assert len(rows) == 1
        assert rows[0][0] is not None
        assert len(rows[0][0]) == 32  # truncated HMAC-SHA256

    def test_verify_audit_integrity(self, tmp_path, monkeypatch) -> None:
        """verify_audit_integrity returns empty list for intact rows."""
        db_path = tmp_path / "test_verify.db"
        monkeypatch.setenv("PICOWATCH_AUDIT_HMAC_KEY", "test-key-that-is-at-least-32-characters-long!")
        config = TelemetryConfig(audit_db_path=db_path)
        sink = TelemetrySink(config=config)

        result = PromptScanResult(
            blocked=False,
            score=0.1,
            rules_matched=[],
            corpus_hash="def789",
            corpus_version="2.0",
            duration_ms=0.5,
        )
        sink.record_prompt_scan(result, request_id="req-verify-1")

        invalid = sink.verify_audit_integrity()
        assert invalid == []

    def test_verify_detects_tampering(self, tmp_path, monkeypatch) -> None:
        """verify_audit_integrity detects tampered rows."""
        db_path = tmp_path / "test_tamper.db"
        monkeypatch.setenv("PICOWATCH_AUDIT_HMAC_KEY", "test-key-that-is-at-least-32-characters-long!")
        config = TelemetryConfig(audit_db_path=db_path)
        sink = TelemetrySink(config=config)

        result = PromptScanResult(
            blocked=True,
            score=0.77,
            rules_matched=["inj_role_override"],
            corpus_hash="xyz",
            corpus_version="2.0",
            duration_ms=3.2,
        )
        sink.record_prompt_scan(result, request_id="req-tamper-1")

        # Tamper with the score in the database
        import sqlite3

        conn = sqlite3.connect(str(db_path))
        conn.execute("UPDATE audit_log SET score = 0.0 WHERE 1=1")
        conn.commit()
        conn.close()

        invalid = sink.verify_audit_integrity()
        assert len(invalid) == 1


class TestAuditWritePersistence:
    """_audit_write: persistent locked connection, retry-once, drop counter."""

    def _result(self) -> PromptScanResult:
        return PromptScanResult(
            blocked=False,
            score=0.2,
            rules_matched=[],
            corpus_hash="abc",
            corpus_version="1.0",
            duration_ms=0.5,
        )

    def test_persistent_connection_reused_across_writes(self, tmp_path, monkeypatch) -> None:
        """Only one sqlite connect for many records (no per-record connect)."""
        import sqlite3

        import picosentry.watch.telemetry.sink as sink_mod

        config = TelemetryConfig(audit_db_path=tmp_path / "audit.db")
        sink = TelemetrySink(config=config)

        real_connect = sqlite3.connect
        calls: list[int] = []

        def counting_connect(*args, **kwargs):
            calls.append(1)
            return real_connect(*args, **kwargs)

        monkeypatch.setattr(sink_mod.sqlite3, "connect", counting_connect)
        for _ in range(5):
            sink.record_prompt_scan(self._result())
        assert len(calls) == 1  # single persistent connection for 5 records

        conn = sqlite3.connect(str(config.audit_db_path))
        assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 5
        conn.close()

    def test_failed_write_increments_dropped_counter_and_logs(self, tmp_path, monkeypatch, caplog) -> None:
        """Final write failure increments dropped_audit_records and logs the count."""
        import logging
        import sqlite3
        from unittest.mock import MagicMock

        import picosentry.watch.telemetry.sink as sink_mod

        config = TelemetryConfig(audit_db_path=tmp_path / "audit.db")
        sink = TelemetrySink(config=config)
        assert sink.dropped_audit_records == 0
        sink._audit_conn = None

        broken = MagicMock()
        broken.execute.side_effect = sqlite3.OperationalError("disk I/O error")
        monkeypatch.setattr(sink_mod.sqlite3, "connect", MagicMock(return_value=broken))

        with caplog.at_level(logging.WARNING, logger="picowatch"):
            sink.record_prompt_scan(self._result())
            sink.record_validation(
                ValidationResult(
                    valid=True,
                    score=0.0,
                    violations=[],
                    corpus_hash="abc",
                    corpus_version="1.0",
                    duration_ms=0.5,
                )
            )

        assert sink.dropped_audit_records == 2
        assert "dropped_audit_records=2" in caplog.text

    def test_transient_database_error_retries_then_succeeds(self, tmp_path) -> None:
        """A stale connection is closed, reopened, and the record lands (self-heal)."""
        import sqlite3

        class StaleConn:
            def execute(self, *args, **kwargs):
                raise sqlite3.OperationalError("database is locked")

            def close(self) -> None:
                pass

        config = TelemetryConfig(audit_db_path=tmp_path / "audit.db")
        sink = TelemetrySink(config=config)
        sink.record_prompt_scan(self._result())  # opens the persistent connection

        stale = StaleConn()
        sink._audit_conn = stale  # type: ignore[assignment]

        sink.record_prompt_scan(self._result())

        assert sink.dropped_audit_records == 0
        assert sink._audit_conn is not stale  # self-healed onto a fresh connection
        conn = sqlite3.connect(str(config.audit_db_path))
        assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 2
        conn.close()

    def test_concurrent_writes_from_threads_do_not_corrupt(self, tmp_path) -> None:
        """Parallel writers serialize on the lock; all rows land, checksums valid."""
        import threading

        config = TelemetryConfig(audit_db_path=tmp_path / "audit.db")
        sink = TelemetrySink(config=config)

        n_threads, per_thread = 8, 10

        def worker(tid: int) -> None:
            for i in range(per_thread):
                sink.record_prompt_scan(
                    PromptScanResult(
                        blocked=False,
                        score=0.1,
                        rules_matched=[],
                        corpus_hash="abc",
                        corpus_version="1.0",
                        duration_ms=0.1,
                        details={"worker": tid, "seq": i},
                    )
                )

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sink.dropped_audit_records == 0
        assert sink.verify_audit_integrity() == []
        import sqlite3

        conn = sqlite3.connect(str(config.audit_db_path))
        assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == n_threads * per_thread
        conn.close()
